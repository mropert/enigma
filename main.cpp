#include "enigma/m4.h"
#include "enigma/solver.h"

#include <chrono>
#include <format>
#include <iostream>
#include <string_view>

// Message P1030681 from Karl Donitz received by U534 in May 1945
constexpr std::string_view donitz_message = "LANOTCTOUARBBFPMHPHGCZXTDYGAHGUFXGEWKBLKGJWLQXXTGPJJAVTOYJFGSLPPQIHZFXOEBWIIEKFZLCLOAQJULJOYHS"
											"SMBBGWHZANVOIIPYRBRTDJQDJJOQKCXWDNBBTYVXLYTAPGVEATXSONPNYNQFUDBBHHVWEPYEYDOHNLXKZDNWRHDUWUJUMW"
											"WVIIWZXIVIUQDRHYMNCYEFUAPNHOTKHKGDNPSAKNUAGHJZSMJBMHVTREQEDGXHLZWIFUSKDQVELNMIMITHBHDBWVHDFYHJ"
											"OQIHORTDJDBWXEMEAYXGYQXOHFDMYUXXNOJAZRSGHPLWMLRECWWUTLRTTVLBHYOORGLGOWUXNXHMHYFAACQEKTHSJW";

constexpr std::string_view donitz_decoded_message = "KRKRALLEXXFOLGENDESISTSOFORTBEKANNTZUGEBENXXICHHABEFOLGENDENBEFEHLERHALTENXXJANSTERLED"
													"ESBISHERIGXNREICHSMARSCHALLSJGOERINGJSETZTDERFUEHRERSIEYHVRRGRZSSADMIRALYALSSEINENNACH"
													"FOLGEREINXSCHRIFTLSCHEVOLLMACHTUNTERWEGSXABSOFORTSOLLENSIESAEMTLICHEMASSNAHMENVERFUEGE"
													"NYDIESICHAUSDERGEGENWAERTIGENLAGEERGEBENXGEZXREICHSLEITEIKKTULPEKKJBORMANNJXXOBXDXMMMD"
													"URNHFKSTXKOMXADMXUUUBOOIEXKP";

void print_settings( const enigma::m4_solver::settings& settings )
{
	std::cout << std::format( "- Rotors: {}, {}, {}, {}\n",
							  settings.m_rotors[ 0 ],
							  settings.m_rotors[ 1 ],
							  settings.m_rotors[ 2 ],
							  settings.m_rotors[ 3 ] );
	std::cout << std::format( "- Ring settings: {}, {}, {}, {}\n",
							  settings.m_ring_settings[ 0 ],
							  settings.m_ring_settings[ 1 ],
							  settings.m_ring_settings[ 2 ],
							  settings.m_ring_settings[ 3 ] );
	std::cout << std::format( "- Message key: {}\n", settings.m_key );
}

auto make_cracking_progress_counter()
{
	return [ last_update_ts = std::chrono::steady_clock::now(),
			 last_update_progress = 0 ]( std::size_t progress, std::size_t total, std::size_t false_positives ) mutable {
		using namespace std::chrono_literals;
		const auto now = std::chrono::steady_clock::now();
		const auto elapsed = now - last_update_ts;
		if ( elapsed > 5s )
		{
			const auto last_progress = progress - last_update_progress;
			const auto average_progress = static_cast<std::size_t>(
				last_progress * 1'000 / std::chrono::duration_cast<std::chrono::milliseconds>( elapsed ).count() );
			const auto ETA = ( total - progress ) / average_progress;
			std::cout << std::format( "Cracking in progress... {} / {} ({} combinations / second, {} false positives)",
									  progress,
									  total,
									  average_progress,
									  false_positives );
			if ( ETA >= 300 )
			{
				std::cout << std::format( " ETA {} minutes\n", ETA / 60 );
			}
			else
			{
				std::cout << std::format( " ETA {} seconds\n", ETA );
			}
			last_update_ts = now;
			last_update_progress = progress;
		}
	};
}

void break_message( std::string_view cyphertext,
					std::string_view plaintext,
					enigma::reflector reflector,
					std::span<const char* const> plugs )
{
	std::cout << std::format( "Cracking message of {} characters with {} threads\n",
							  cyphertext.size(),
							  std::thread::hardware_concurrency() );

	auto on_update = make_cracking_progress_counter();

	const auto settings = enigma::m4_solver::crack_settings( cyphertext, reflector, plugs, plaintext, on_update );

	if ( settings )
	{
		std::cout << "Cracked message!\n";
		print_settings( *settings );
	}
	else
	{
		std::cout << "*** FAILED TO CRACK ENIGMA SETTINGS ***\n";
	}
}

void break_message_with_crib( std::string_view cyphertext,
							  std::string_view plaintext,
							  enigma::reflector reflector,
							  std::span<const char* const> plugs,
							  std::string_view crib,
							  std::size_t hint = 0 )
{
	using namespace enigma;

	const auto cyphertext_with_hint = cyphertext.substr( hint );

	const auto locations = find_potential_crib_location( cyphertext_with_hint, crib );

	if ( locations.empty() )
	{
		std::cout << std::format( "No potential location for crib {} in message!\n", crib );
		return;
	}

	std::cout << std::format( "Cracking message of {} characters using crib {} ({} potential locations) with {} threads\n",
							  cyphertext_with_hint.size(),
							  crib,
							  locations.size(),
							  std::thread::hardware_concurrency() );

	auto on_update = make_cracking_progress_counter();

	auto settings = m4_solver::crack_settings_with_crib( cyphertext_with_hint, reflector, plugs, crib, locations, on_update );
	if ( !settings )
	{
		// No dice, probably wrong crib guess
		std::cout << "*** FAILED TO FIND MATCHING SETTINGS FOR CRIB ***\n";
		return;
	}

	if ( hint > 0 )
	{
		auto partial_settings = *settings;
		settings.reset();
		// Fix up key to account for rotor position at hint start
		const m4_machine machine( { rotors[ partial_settings.m_rotors[ 0 ] ],
									rotors[ partial_settings.m_rotors[ 1 ] ],
									rotors[ partial_settings.m_rotors[ 2 ] ],
									rotors[ partial_settings.m_rotors[ 3 ] ] },
								  partial_settings.m_ring_settings,
								  reflector,
								  plugs );
		const auto candidate_key = machine.rollback_key( partial_settings.m_key, hint );

		partial_settings.m_key = candidate_key;

		// Rollback can sometimes yield incorrect 2nd and 3rd letter if we guessed middle right ring setting wrong
		// Try fine tuning with nearby letters
		for ( int middle_left_offset = -2; !settings && middle_left_offset <= 2; ++middle_left_offset )
		{
			partial_settings.m_key[ 1 ] = 'A' + ( ( candidate_key[ 1 ] - 'A' + middle_left_offset + 26 ) % 26 );

			for ( int middle_right_offset = -2; !settings && middle_right_offset <= 2; ++middle_right_offset )
			{
				partial_settings.m_key[ 2 ] = 'A' + ( ( candidate_key[ 2 ] - 'A' + middle_right_offset + 26 ) % 26 );

				settings = m4_solver::fine_tune_key( cyphertext, partial_settings, reflector, plugs, plaintext );
			}
		}
	}

	if ( settings )
	{
		std::cout << "Cracked message!\n";
		print_settings( *settings );
		return;
	}

	std::cout << "*** FAILED TO FIND MATCHING SETTINGS FOR CRIB ***\n";
}

void compute_partial_scores()
{
	using namespace enigma;

	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	for ( int i = 1; i <= 10; ++i )
	{
		const auto length = static_cast<std::size_t>( donitz_message.size() * 0.1f * i );
		const auto cyphertext = donitz_message.substr( 0, length );
		const auto plaintext = donitz_decoded_message.substr( 0, length );

		const auto reference_score = [ & ] {
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "AAAA" );
			return partial_match_score( plaintext, result );
		}();

		std::cout << std::format( "Message length: {}, Ref: {}, Ref / Length: {:.3f}\n",
								  length,
								  reference_score,
								  static_cast<float>( reference_score ) / length );

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YAAA" );
			const auto score = partial_match_score( plaintext, result );
			std::cout << std::format( "2/1: {} ({:.2f})", score, static_cast<float>( score ) / reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOAA" );
			const auto score = partial_match_score( plaintext, result );
			std::cout << std::format( ", 2/2: {} ({:.2f})", score, static_cast<float>( score ) / reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOOA" );
			const auto score = partial_match_score( plaintext, result );
			std::cout << std::format( ", 2/3: {} ({:.2f})", score, static_cast<float>( score ) / reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOOO" );
			const auto score = partial_match_score( plaintext, result );
			std::cout << std::format( ", 2/4: {} ({:.2f})", score, static_cast<float>( score ) / reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 11 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOOZ" );
			const auto score = partial_match_score( plaintext, result );
			std::cout << std::format( ", 3/4: {} ({:.2f})", score, static_cast<float>( score ) / reference_score );
		}

		std::cout << std::endl;
	}
}

std::string partial_decrypt_at( std::string_view key, std::size_t start, std::size_t location, std::size_t length, const std::span<const char* const> plugs )
{
	using namespace enigma;
	constexpr std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	constexpr std::array ring_settings = { 0, 0, 4, 11 };

	m4_machine machine( wheels, ring_settings, reflectors::C, plugs );
	auto new_key = machine.advance_key( key, start );

	for ( int i = 0; i < 4; ++i )
	{
		new_key[ i ] = ( new_key[ i ] - 'A' - ring_settings[ i ] ) % 26 + 'A';
	}

	machine = { wheels, { 0, 0, 0, 0 }, reflectors::C, plugs };
	return machine.decode( donitz_message.substr( start, location - start + length ), new_key ).substr( location - start );
}

std::string format_partial_decrypt( std::string_view plaintext, std::string_view candidate )
{
	std::string result;
	result.reserve( candidate.size() );

	for ( int i = 0; i < candidate.size(); ++i )
	{
		result += candidate[ i ] == plaintext[ i ] ? candidate[ i ] : '*';
	}

	return result;
}

void display_partial_decrypt_with_crib_at( std::string_view crib, std::size_t start, std::size_t location, std::span<const char* const> plugs )
{
	using enigma::partial_match_score;

	{
		const auto crib_out = partial_decrypt_at( "AAAA", start, location, crib.size(), plugs );
		std::cout << std::format( "0: {} (score: {})\n", format_partial_decrypt( crib, crib_out ), partial_match_score( crib, crib_out ) );
	}

	{
		const auto crib_out = partial_decrypt_at( "YAAA", start, location, crib.size(), plugs );
		std::cout << std::format( "1: {} (score: {})\n", format_partial_decrypt( crib, crib_out ), partial_match_score( crib, crib_out ) );
	}

	{
		const auto crib_out = partial_decrypt_at( "YOAA", start, location, crib.size(), plugs );
		std::cout << std::format( "2: {} (score: {})\n", format_partial_decrypt( crib, crib_out ), partial_match_score( crib, crib_out ) );
	}

	{
		const auto crib_out = partial_decrypt_at( "YOSA", start, location, crib.size(), plugs );
		std::cout << std::format( "3: {} (score: {})\n", format_partial_decrypt( crib, crib_out ), partial_match_score( crib, crib_out ) );
	}

	{
		const auto crib_out = partial_decrypt_at( "YOSZ", start, location, crib.size(), plugs );
		std::cout << std::format( "4: {} (score: {})\n", format_partial_decrypt( crib, crib_out ), partial_match_score( crib, crib_out ) );
	}
}

void display_partial_decrypt_with_crib( std::string_view crib, std::size_t hint )
{
	using namespace enigma;

	const auto location = donitz_decoded_message.find( crib );
	auto locations = find_potential_crib_location( donitz_message, crib );
	std::erase_if( locations, [ hint ]( std::size_t loc ) { return loc < hint; } );

	constexpr std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };


	std::cout << std::format( "Crib: {}, length: {}, hint: {}, first guess {}, correct location: {}\n",
							  crib,
							  crib.size(),
							  hint,
							  locations[ 0 ],
							  location );

	std::cout << std::format( "With plugboard from location (ref score: {})\n", partial_match_reference_score( crib.size() ) );
	display_partial_decrypt_with_crib_at( crib, location, location, plugs );

	std::cout << std::format( "With plugboard from hint (ref score: {})\n", partial_match_reference_score( crib.size() ) );
	display_partial_decrypt_with_crib_at( crib, hint, location, plugs );

	std::cout << std::format( "Without plugboard from location (ref score: {})\n", crib.size() / 10 );
	display_partial_decrypt_with_crib_at( crib, location, location, {} );
}


int main( int argc, char** argv )
{
	using namespace std::literals;

	//constexpr std::string_view crib = "XGEZXREICHSLEITEIKKTULPEKKJBORMANNJXX";
	//constexpr std::size_t hint = donitz_message.size() * 0.75f;
	constexpr std::string_view crib = "REICHSMARSCHALLSJGOERINGJ";
	constexpr std::size_t hint = 0;
	//constexpr std::string_view crib = "REICHSMARSCHALL";

	if ( argc >= 2 && argv[ 1 ] == "-scores"sv )
	{
		compute_partial_scores();
	}
	else if ( argc >= 2 && argv[ 1 ] == "-partial"sv )
	{
		display_partial_decrypt_with_crib( crib, hint );
	}
	else
	{
		constexpr std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

		if ( argc >= 2 && argv[ 1 ] == "-crib"sv )
		{
			break_message_with_crib( donitz_message, donitz_decoded_message, enigma::reflectors::C, plugs, crib, hint );
		}
		else if ( argc >= 2 && argv[ 1 ] == "-plugboard"sv )
		{
			break_message( donitz_message, donitz_decoded_message, enigma::reflectors::C, {} );
		}
		else
		{
			break_message( donitz_message, donitz_decoded_message, enigma::reflectors::C, plugs );
		}
	}


	return 0;
}
