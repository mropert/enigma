#include <catch.hpp>

#include "enigma/m4.h"
#include "enigma/solver.h"

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

	m4_machine machine( wheels, { 0, 0, 4, 11 }, reflectors::C, plugs );
	const auto result = machine.decode( donitz_message, "YOSZ" );

	REQUIRE( result == donitz_decoded_message );
}

TEST_CASE( "Partially Decode Donitz message with M4 and wrong ring settings", "[m4]" )
{


	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

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

TEST_CASE( "Bruteforce Donitz message key", "[m4]" )
{
	const std::array<rotor, 4> wheels = { rotors[ 9 ], rotors[ 5 ], rotors[ 6 ], rotors[ 8 ] };
	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };

	const auto key = m4_solver::brute_force_key( donitz_message, wheels, { 0, 0, 4, 11 }, reflectors::C, plugs, donitz_decoded_message );

	REQUIRE( key == "YOSZ" );
}
