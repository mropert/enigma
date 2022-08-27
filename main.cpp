#include "enigma/m4.h"
#include "enigma/solver.h"

#include <iostream>
#include <string>

// Message P1030681 from Karl Donitz received by U534 in May 1945
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

int main( int, char** )
{
	using namespace enigma;

	const std::array plugs = { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" };
	const auto settings = m4_solver::brute_force( donitz_message, reflectors::C, plugs, donitz_decoded_message );

	std::cout << "Cracked message!" << std::endl;
	std::cout << "- Rotors: " << settings.m_rotors[ 0 ] << ", " << settings.m_rotors[ 1 ] << ", " << settings.m_rotors[ 2 ] << ", "
			  << settings.m_rotors[ 3 ] << std::endl;
	std::cout << "- Ring settings: " << settings.m_ring_settings[ 0 ] << ", " << settings.m_ring_settings[ 1 ] << ", "
			  << settings.m_ring_settings[ 2 ] << ", " << settings.m_ring_settings[ 3 ] << std::endl;
	std::cout << "- Message key: " << settings.m_key << std::endl;

	return 0;
}
