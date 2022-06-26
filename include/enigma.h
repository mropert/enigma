#include <array>
#include <span>
#include <string>
#include <string_view>

namespace enigma
{
	struct rotor
	{
		constexpr rotor( std::string_view wiring, std::array<char, 2> turnover )
			: m_turnovers( turnover )
		{
			// Repeat wiring 3 times to avoid modulo in computation
			for ( int i = 0; i < 3; ++i )
			{
				for ( int j = 0; j < 26; ++j )
				{
					m_wiring[ j + ( i * 26 ) ] = wiring[ j ];
					m_reversed_wiring[ wiring[ j ] - 'A' + ( i * 26 ) ] = 'A' + j;
				}
			}
		}

		std::array<char, 26 * 3> m_wiring;
		std::array<char, 26 * 3> m_reversed_wiring;
		std::array<char, 2> m_turnovers;
	};

	static constexpr std::array<rotor, 11> rotors = {
		rotor { "ABCDEFGHIJKLMNOPQRSTUVWXYZ", { 0, -1 } }, { "EKMFLGDQVZNTOWYHXUSPAIBRCJ", { 16, -1 } },
		{ "AJDKSIRUXBLHWTMCQGZNPYFVOE", { 4, -1 } },	   { "BDFHJLCPRTXVZNYEIWGAKMUSQO", { 21, -1 } },
		{ "ESOVPZJAYQUIRHXLNFTGKDCMWB", { 9, -1 } },	   { "VZBRGITYUPSDNHLXAWMJQOFECK", { 25, -1 } },
		{ "JPGVOUMFYQBENHZRDKASXLICTW", { 12, 25 } },	   { "NZJHGRCXMYSWBOUFAIVLPEKQDT", { 12, 25 } },
		{ "FKQHTLXOCBJSPDZRAMEWNIUYGV", { 12, 25 } },	   { "LEYJVCNIXWPBQMDRTAKZGFUHOS", { -1, 25 } },
		{ "FSOKANUERHMBTIYCWLQPZXVGJD", { -1, -1 } }
	};

	enum class rotor_index
	{
		ETW = 0,
		I,
		II,
		III,
		IV,
		V,
		VI,
		VII,
		VIII,
		Beta,
		Gamma
	};

	namespace reflectors
	{
		static constexpr std::string_view B = "ENKQAUYWJICOPBLMDXZVFTHRGS";
		static constexpr std::string_view C = "RDOBJNTKVEHMLFCWZAXGYIPSUQ";
	}


	struct m4_machine
	{
		m4_machine( const std::array<rotor, 4>& rotors,
					std::array<char, 4> ring_settings,
					std::string_view reflector,
					std::span<const char* const> plugs );

		std::string decode( std::string_view message, std::string_view key );

		std::array<rotor, 4> m_rotors;
		std::array<char, 4> m_rings_settings;
		std::string_view m_reflector;
		std::array<char, 26> m_plugboard;
	};

}
