#include "enigma/m4.h"
#include "enigma/solver.h"

#include <catch.hpp>

using namespace enigma;

const std::string donitz_message = "LANOTCTOUARBBFPMHPHGCZXTDYGAHGUFXGEWKBLKGJWLQXXTGPJJAVTOYJFGSLPPQIHZFXOEBWIIEKFZLCLOAQJULJOYHSSMBBGWHZA"
								   "NVO"
								   "IIPYRBRTDJQDJJOQKCXWDNBBTYVXLYTAPGVEATXSONPNYNQFUDBBHHVWEPYEYDOHNLXKZD"
								   "NWRHDUWUJUMWWVIIWZXIVIUQDRHYMNCYEFUAPNHOTKHKGDNPSAKNUAGHJZSMJBMHVTREQEDGXHLZWIFUSKDQVELNMIMITHBHDBWVHDF"
								   "YHJ"
								   "OQIHORTDJDBWXEMEAYXGYQXOHFDMYUXXNOJAZRSGHPLWMLRECWWUTLRTTVLBHYOORGLGOW"
								   "UXNXHMHYFAACQEKTHSJW";

const std::string donitz_decoded_message = "KRKRALLEXXFOLGENDESISTSOFORTBEKANNTZUGEBENXXICHHABEFOLGENDENBEFEHLERHALTENXXJANSTERLEDESBISHERI"
										   "GXN"
										   "REICHSMARSCHALLSJGOERINGJSETZTDERFUEHRERSIEYHVRRGRZSSADMIRALYALSSEINENNACHFOLGEREINXSCHRIFTLSCH"
										   "EVO"
										   "LLMACHTUNTERWEGSXABSOFORTSOLLENSIESAEMTLICHEMASSNAHMENVERFUEGENYDIESICHAUSDERGEGENWAERTIGENLAGE"
										   "ERG"
										   "EBENXGEZXREICHSLEITEIKKTULPEKKJBORMANNJXXOBXDXMMMDURNHFKSTXKOMXADMXUUUBOOIEXKP";

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

	const auto reference_score = [ & ]
	{
		m4_machine machine( wheels, { 0, 0, 0, 0 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "AAAA" );
		return partial_match_score( donitz_decoded_message, result );
	}();

	{
		m4_machine machine( wheels, { 0, 0, 0, 11 }, reflectors::C, plugs );
		const auto result = machine.decode( donitz_message, "YOOZ" );
		const auto score = partial_match_score( donitz_decoded_message, result );

		REQUIRE( score > reference_score * 10 );
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
	}

	{
		const auto result = m4_solver::fine_tune_key( donitz_message,
													  { wheels, { 0, 0, 0, 25 }, "YOPN" },
													  reflectors::C,
													  plugs,
													  donitz_decoded_message );
		REQUIRE( result );
		m4_machine machine( { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] }, result->m_ring_settings, reflectors::C, plugs );
		const auto decoded_message = machine.decode( donitz_message, result->m_key );
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

#ifndef _DEBUG

TEST_CASE( "Bruteforce Donitz message key", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	const auto key = m4_solver::brute_force_key( donitz_message, wheels, { 0, 0, 4, 11 }, reflectors::C, plugs, donitz_decoded_message );

	REQUIRE( key == "YOSZ" );
}

#endif