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

	const auto settings = enigma::m4_solver::brute_force( cyphertext, reflector, plugs, plaintext, on_update );

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

std::optional<enigma::m4_solver::settings> try_break_message_with_crib_at( std::string_view cyphertext,
																		   std::string_view plaintext,
																		   enigma::reflector reflector,
																		   std::span<const char* const> plugs,
																		   std::string_view crib,
																		   std::size_t crib_location )
{
	using namespace enigma;

	const auto crib_cyphertext = cyphertext.substr( crib_location, crib.size() );

	auto on_update = make_cracking_progress_counter();

	auto settings = m4_solver::brute_force( crib_cyphertext, reflector, plugs, crib, on_update );
	if ( !settings )
	{
		// No dice, probably wrong crib guess
		return std::nullopt;
	}

	// Fix up key to account for rotor position at crib start
	const m4_machine machine( { rotors[ settings->m_rotors[ 0 ] ],
								rotors[ settings->m_rotors[ 1 ] ],
								rotors[ settings->m_rotors[ 2 ] ],
								rotors[ settings->m_rotors[ 3 ] ] },
							  settings->m_ring_settings,
							  reflector,
							  plugs );
	const auto candidate_key = machine.rollback_key( settings->m_key, crib_location );

	settings->m_key = candidate_key;

	// Rollback can sometimes yield incorrect 2nd and 3rd letter if we guessed middle right ring setting wrong
	// Try fine tuning with nearby letters
	for ( int middle_left_offset = -2; middle_left_offset <= 2; ++middle_left_offset )
	{
		settings->m_key[ 1 ] = 'A' + ( ( candidate_key[ 1 ] - 'A' + middle_left_offset + 26 ) % 26 );

		for ( int middle_right_offset = -2; middle_right_offset <= 2; ++middle_right_offset )
		{
			settings->m_key[ 2 ] = 'A' + ( ( candidate_key[ 2 ] - 'A' + middle_right_offset + 26 ) % 26 );

			const auto final_settings = m4_solver::fine_tune_key( cyphertext, *settings, reflector, plugs, plaintext );
			if ( final_settings )
			{
				return final_settings;
			}
		}
	}

	return std::nullopt;
}

void break_message_with_crib( std::string_view cyphertext,
							  std::string_view plaintext,
							  enigma::reflector reflector,
							  std::span<const char* const> plugs,
							  std::string_view crib,
							  std::size_t hint = 0 )
{
	using namespace enigma;

	auto locations = find_potential_crib_location( cyphertext, crib );
	std::erase_if( locations, [ hint ]( std::size_t location ) { return location < hint; } );

	if ( locations.empty() )
	{
		std::cout << std::format( "No potential location for crib {} in message!\n", crib );
		return;
	}

	std::cout << std::format( "Cracking message of {} characters using crib {} with {} threads\n",
							  cyphertext.size(),
							  crib,
							  std::thread::hardware_concurrency() );

	for ( int i = 0; i < locations.size(); ++i )
	{
		std::cout << std::format( "\nTrying crib position {} out of {} (offset {})\n", i, locations.size(), locations[ i ] );
		const auto settings = try_break_message_with_crib_at( cyphertext, plaintext, reflector, plugs, crib, locations[ i ] );

		if ( settings )
		{
			std::cout << "Cracked message!\n";
			print_settings( *settings );
			return;
		}
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


int main( int argc, char** argv )
{
	using namespace std::literals;

	if ( argc >= 2 && argv[ 1 ] == "-scores"sv )
	{
		compute_partial_scores();
	}
	else
	{
		constexpr std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

		if ( argc >= 2 && argv[ 1 ] == "-crib"sv )
		{
			constexpr std::string_view crib = "XGEZXREICHSLEITEIKKTULPEKKJBORMANNJXX";
			constexpr std::size_t hint = donitz_message.size() * 0.75f;
			//constexpr std::string_view crib = "REICHSMARSCHALLSJGOERINGJ";
			//constexpr std::string_view crib = "REICHSMARSCHALL";

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
