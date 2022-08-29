#include "enigma/m4.h"
#include "enigma/solver.h"

#include <chrono>
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

	auto last_update_ts = std::chrono::steady_clock::now();
	std::size_t last_update_progress = 0;

	auto on_update = [ & ]( std::size_t progress, std::size_t total )
	{
		using namespace std::chrono_literals;
		const auto now = std::chrono::steady_clock::now();
		const auto elapsed = now - last_update_ts;
		if ( elapsed > 2s )
		{
			const auto last_progress = progress - last_update_progress;
			const auto average_progress = static_cast<std::size_t>(
				last_progress / ( 2'000'000. / std::chrono::duration_cast<std::chrono::microseconds>( elapsed ).count() ) );
			std::cout << "Cracking in progress... " << progress << '/' << total << " (" << average_progress << " combinations / second, ETA "
					  << ( total - progress ) / average_progress / 60 << " minutes)" << std::endl;
			last_update_ts = now;
			last_update_progress = progress;
		}
	};

	const auto settings = m4_solver::brute_force( donitz_message, reflectors::C, plugs, donitz_decoded_message, on_update );

	std::cout << "Cracked message!" << std::endl;
	std::cout << "- Rotors: " << settings.m_rotors[ 0 ] << ", " << settings.m_rotors[ 1 ] << ", " << settings.m_rotors[ 2 ] << ", "
			  << settings.m_rotors[ 3 ] << std::endl;
	std::cout << "- Ring settings: " << settings.m_ring_settings[ 0 ] << ", " << settings.m_ring_settings[ 1 ] << ", "
			  << settings.m_ring_settings[ 2 ] << ", " << settings.m_ring_settings[ 3 ] << std::endl;
	std::cout << "- Message key: " << settings.m_key << std::endl;

	return 0;
}
