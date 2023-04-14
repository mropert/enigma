#include "enigma/m4.h"
#include "enigma/solver.h"

#include <catch.hpp>

using namespace enigma;

constexpr std::string_view donitz_message = "LANOTCTOUARBBFPMHPHGCZXTDYGAHGUFXGEWKBLKGJWLQXXTGPJJAVTOYJFGSLPPQIHZFXOEBWIIEKFZLCLOAQJULJOYHS"
											"SMBBGWHZANVOIIPYRBRTDJQDJJOQKCXWDNBBTYVXLYTAPGVEATXSONPNYNQFUDBBHHVWEPYEYDOHNLXKZDNWRHDUWUJUMW"
											"WVIIWZXIVIUQDRHYMNCYEFUAPNHOTKHKGDNPSAKNUAGHJZSMJBMHVTREQEDGXHLZWIFUSKDQVELNMIMITHBHDBWVHDFYHJ"
											"OQIHORTDJDBWXEMEAYXGYQXOHFDMYUXXNOJAZRSGHPLWMLRECWWUTLRTTVLBHYOORGLGOWUXNXHMHYFAACQEKTHSJW";

constexpr std::string_view donitz_decoded_message = "KRKRALLEXXFOLGENDESISTSOFORTBEKANNTZUGEBENXXICHHABEFOLGENDENBEFEHLERHALTENXXJANSTERLED"
													"ESBISHERIGXNREICHSMARSCHALLSJGOERINGJSETZTDERFUEHRERSIEYHVRRGRZSSADMIRALYALSSEINENNACH"
													"FOLGEREINXSCHRIFTLSCHEVOLLMACHTUNTERWEGSXABSOFORTSOLLENSIESAEMTLICHEMASSNAHMENVERFUEGE"
													"NYDIESICHAUSDERGEGENWAERTIGENLAGEERGEBENXGEZXREICHSLEITEIKKTULPEKKJBORMANNJXXOBXDXMMMD"
													"URNHFKSTXKOMXADMXUUUBOOIEXKP";

TEST_CASE( "Decode Donitz message with M4", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	{
		m4_machine machine( wheels, { 0, 0, 4, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOSZ" );

		REQUIRE( result == donitz_decoded_message );
	}
	{
		m4_machine machine( wheels, { 0, 0, 4, 24 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOSM" );

		REQUIRE( result == donitz_decoded_message );
	}
	{
		m4_machine machine( wheels, { 0, 0, 17, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOFZ" );

		REQUIRE( result == donitz_decoded_message );
	}
}

TEST_CASE( "Partially Decode Donitz message with M4 and wrong ring settings", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	{
		m4_machine machine( wheels, { 0, 0, 0, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOOZ" );

		int matches = 0;
		for ( int i = 0; i < result.size(); ++i )
		{
			if ( result[ i ] == donitz_decoded_message[ i ] )
			{
				++matches;
			}
		}

		REQUIRE( matches > result.size() / 2 );
	}
	{
		m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOOO" );

		int matches = 0;
		for ( int i = 0; i < result.size(); ++i )
		{
			if ( result[ i ] == donitz_decoded_message[ i ] )
			{
				++matches;
			}
		}

		REQUIRE( matches > result.size() / 8 );
	}
}

TEST_CASE( "Partially wrong settings give higher score than bad settings", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	for ( int i = 1; i <= 10; ++i )
	{
		const auto length = static_cast<std::size_t>( donitz_message.size() * 0.1f * i );
		const auto cyphertext = donitz_message.substr( 0, length );
		const auto plaintext = donitz_decoded_message.substr( 0, length );

		const auto reference_score = partial_match_reference_score( length );

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YAAA" );
			const auto score = partial_match_score( plaintext, result );

			REQUIRE( score < reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOAA" );
			const auto score = partial_match_score( plaintext, result );

			REQUIRE( score < reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOOA" );
			const auto score = partial_match_score( plaintext, result );

			REQUIRE( score < reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 11 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOOZ" );
			const auto score = partial_match_score( plaintext, result );

			REQUIRE( score >= reference_score );
		}

		{
			m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
			const auto result = machine.decode( cyphertext, "YOOO" );
			const auto score = partial_match_score( plaintext, result );

			REQUIRE( score >= reference_score );
		}
	}
}

TEST_CASE( "Solver can fine tune partially matched settings", "[m4]" )
{
	const std::array<int, 4> wheels = { 9, 5, 6, 8 };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	{
		const auto result = m4_solver::fine_tune_key( donitz_message,
													  { wheels, { 0, 0, 0, 11 }, "YOOZ" },
													  reflectors::C,
													  plugs,
													  donitz_decoded_message );
		REQUIRE( result );
		m4_machine machine( { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] }, result->m_ring_settings, reflectors::C, plugs );
		const auto decoded_message = machine.decode( donitz_message, result->m_key );
		REQUIRE( decoded_message == donitz_decoded_message );
	}

	{
		const auto result = m4_solver::fine_tune_key( donitz_message,
													  { wheels, { 0, 0, 0, 0 }, "YOOO" },
													  reflectors::C,
													  plugs,
													  donitz_decoded_message );
		REQUIRE( result );
		m4_machine machine( { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] }, result->m_ring_settings, reflectors::C, plugs );
		const auto decoded_message = machine.decode( donitz_message, result->m_key );
		REQUIRE( decoded_message == donitz_decoded_message );
	}

	{
		const auto result = m4_solver::fine_tune_key( donitz_message,
													  { wheels, { 0, 0, 0, 25 }, "YOON" },
													  reflectors::C,
													  plugs,
													  donitz_decoded_message );
		REQUIRE( result );
		m4_machine machine( { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] }, result->m_ring_settings, reflectors::C, plugs );
		const auto decoded_message = machine.decode( donitz_message, result->m_key );
		REQUIRE( decoded_message == donitz_decoded_message );
	}
}

TEST_CASE( "Wrong plugboard settings with right key still give higher match score", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };
	{
		m4_machine machine( wheels, { 0, 0, 4, 11 }, reflectors::C, {} );
		const auto result = machine.decode( donitz_message, "YOSZ" );
		const int score = unknown_plugboard_match_score( donitz_decoded_message, result );
		REQUIRE( score >= result.size() / 13 );
	}
	{
		m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, {} );
		const auto result = machine.decode( donitz_message, "AAAA" );
		const int score = unknown_plugboard_match_score( donitz_decoded_message, result );
		REQUIRE( score < result.size() / 13 );
	}
	{
		// False positive settings found during testing
		m4_machine machine( { rotors[ 9 ], rotors[ 1 ], rotors[ 2 ], rotors[ 3 ] }, { 0, 0, 0, 24 }, reflectors::C, {} );
		const auto result = machine.decode( donitz_message, "PJZG" );
		const int score = unknown_plugboard_match_score( donitz_decoded_message, result );
		REQUIRE( score < result.size() / 13 );
	}
	{
		// False positive settings found during testing
		m4_machine machine( wheels, { 0, 0, 4, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "BISZ" );
		const int score = unknown_plugboard_match_score( donitz_decoded_message, result );
		REQUIRE( score < result.size() / 13 );
	}
}

TEST_CASE( "Index of coincidence is higher with the right settings", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };
	{
		m4_machine machine( wheels, { 0, 0, 4, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOSZ" );
		const float score = index_of_coincidence( result );
		REQUIRE( score > 1.3f );
	}
	{
		m4_machine machine( wheels, { 0, 0, 0, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOOZ" );
		const float score = index_of_coincidence( result );
		REQUIRE( score > 1.2f );
	}
	{
		m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "AAAA" );
		const float score = index_of_coincidence( result );
		REQUIRE( score < 1.1f );
	}
	{
		m4_machine machine( { rotors[ 10 ], rotors[ 1 ], rotors[ 2 ], rotors[ 3 ] }, { 0, 0, 0, 0 }, reflectors::C, {} );
		const auto result = machine.decode( donitz_message, "AAAA" );
		const float score = index_of_coincidence( result );
		REQUIRE( score < 1.1f );
	}
}

TEST_CASE( "Finding potential crib location", "[m4]" )
{
	constexpr std::string_view crib = "XGEZXREICHSLEITEIKKTULPEKKJBORMANNJXX";
	constexpr int correct_location = donitz_decoded_message.find( crib );
	const auto locations = find_potential_crib_location( donitz_message, crib );

	REQUIRE( std::find( begin( locations ), end( locations ), correct_location ) != end( locations ) );

	std::vector<std::size_t> filtered_locations;
	std::copy_if( begin( locations ), end( locations ), std::back_inserter( filtered_locations ), []( std::size_t location ) {
		return location >= donitz_message.size() * 0.75f;
	} );

	REQUIRE( std::find( begin( filtered_locations ), end( filtered_locations ), correct_location ) != end( filtered_locations ) );
}

TEST_CASE( "M4 machine can roll back key strokes and return original key", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const m4_machine machine( wheels, { 0, 0, 4, 11 }, reflectors::C, {} );

	const auto original_key = machine.rollback_key( "YQRL", 298 );
	REQUIRE( original_key == "YOSZ" );

	const auto offset_key = machine.advance_key( "YOSZ", 298 );
	REQUIRE( offset_key == "YQRL" );
}


#ifndef _DEBUG

TEST_CASE( "Bruteforce Donitz message key", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	const auto keys = m4_solver::crack_key( donitz_message, wheels, { 0, 0, 4, 11 }, reflectors::C, plugs, donitz_decoded_message );

	REQUIRE( std::find( begin( keys ), end( keys ), "YOSZ" ) != std::end( keys ) );
}

#endif