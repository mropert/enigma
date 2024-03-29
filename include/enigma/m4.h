#pragma once

#include <algorithm>
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

	struct reflector
	{
		explicit constexpr reflector( std::string_view wiring )
		{
			std::copy_n( begin( wiring ), 26, begin( m_wiring ) );
			std::copy_n( begin( wiring ), 26, begin( m_wiring ) + 26 );
			std::copy_n( begin( wiring ), 26, begin( m_wiring ) + ( 26 * 2 ) );
		}
		std::array<char, 26 * 3> m_wiring;
	};

	namespace reflectors
	{
		static constexpr reflector B( "ENKQAUYWJICOPBLMDXZVFTHRGS" );
		static constexpr reflector C( "RDOBJNTKVEHMLFCWZAXGYIPSUQ" );
	}


	class m4_machine
	{
	public:
		m4_machine( const std::array<rotor, 4>& rotors,
					std::array<int, 4> ring_settings,
					reflector reflector,
					std::span<const char* const> plugs );

		void decode( std::string_view message, std::string_view key, std::string& output ) const;
		// Convenience method for one shot decodes (no ouput buffer reuse)
		[[nodiscard]] std::string decode( std::string_view message, std::string_view key ) const;

		[[nodiscard]] std::string advance_key( std::string_view key, std::size_t position ) const;
		[[nodiscard]] std::string rollback_key( std::string_view key, std::size_t position ) const;

	private:
		std::array<rotor, 4> m_rotors;
		std::array<int, 4> m_rings_settings;
		reflector m_reflector;
		std::array<char, 26> m_plugboard;
	};
}
