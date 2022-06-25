#include "enigma.h"

using enigma::m4_machine;

namespace rotors
{
	const char ETW[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char I[] = "EKMFLGDQVZNTOWYHXUSPAIBRCJ";
	const char II[] = "AJDKSIRUXBLHWTMCQGZNPYFVOE";
	const char III[] = "BDFHJLCPRTXVZNYEIWGAKMUSQO";
	const char IV[] = "ESOVPZJAYQUIRHXLNFTGKDCMWB";
	const char V[] = "VZBRGITYUPSDNHLXAWMJQOFECK";
	const char VI[] = "JPGVOUMFYQBENHZRDKASXLICTW";
	const char VII[] = "NZJHGRCXMYSWBOUFAIVLPEKQDT";
	const char VIII[] = "FKQHTLXOCBJSPDZRAMEWNIUYGV";
	const char Beta[] = "LEYJVCNIXWPBQMDRTAKZGFUHOS";
	const char Gamma[] = "FSOKANUERHMBTIYCWLQPZXVGJD";
}

namespace reflectors
{
	const char B[] = "ENKQAUYWJICOPBLMDXZVFTHRGS";
	const char C[] = "RDOBJNTKVEHMLFCWZAXGYIPSUQ";
}

m4_machine::m4_machine()
	: m_wheels( {
		rotors::Beta,
		rotors::V,
		rotors::VI,
		rotors::VIII,
	} )
	, m_reflector( reflectors::C )
{
	m_wheels_positions[ 0 ] = 'Y' - 'A';
	m_wheels_positions[ 1 ] = 'O' - 'A';
	m_wheels_positions[ 2 ] = 'S' - 'A';
	m_wheels_positions[ 3 ] = 'Z' - 'A';

	m_rings_settings[ 0 ] = 'A' - 'A';
	m_rings_settings[ 1 ] = 'A' - 'A';
	m_rings_settings[ 2 ] = 'E' - 'A';
	m_rings_settings[ 3 ] = 'L' - 'A';

	m_turnovers[ 0 ] = { -1, -1 };
	m_turnovers[ 1 ] = { ( 25 + 26 - m_rings_settings[ 1 ] ) % 26, -1 };
	m_turnovers[ 2 ] = { ( 12 + 26 - m_rings_settings[ 2 ] ) % 26, ( 25 + 26 - m_rings_settings[ 2 ] ) % 26 };
	m_turnovers[ 3 ] = { ( 12 + 26 - m_rings_settings[ 3 ] ) % 26, ( 25 + 26 - m_rings_settings[ 3 ] ) % 26 };

	for ( int i = 0; i < m_wheels.size(); ++i )
	{
		m_reversed_wheels[ i ].resize( m_wheels[ i ].size(), 0 );
		for ( int j = 0; j < m_wheels[ i ].size(); ++j )
		{
			m_reversed_wheels[ i ][ m_wheels[ i ][ j ] - 'A' ] = 'A' + j;
		}
	}

	for ( int i = 0; i < m_plugboard.size(); ++i )
	{
		m_plugboard[ i ] = 'A' + i;
	}

	for ( auto pPair : { "AE", "BF", "CM", "DQ", "HU", "JN", "LX", "PR", "SZ", "VW" } )
	{
		m_plugboard[ pPair[ 0 ] - 'A' ] = pPair[ 1 ];
		m_plugboard[ pPair[ 1 ] - 'A' ] = pPair[ 0 ];
	}
}

std::string m4_machine::decode( const std::string& message )
{
	std::string result;
	result.reserve( message.size() );

	std::array<int, 4> offsets = { m_wheels_positions[ 0 ] - m_rings_settings[ 0 ],
								   m_wheels_positions[ 1 ] - m_rings_settings[ 1 ],
								   m_wheels_positions[ 2 ] - m_rings_settings[ 2 ],
								   m_wheels_positions[ 3 ] - m_rings_settings[ 3 ] };

	for ( const auto character : message )
	{
		char input = character;

		if ( m_turnovers[ 3 ][ 0 ] == ( offsets[ 3 ] % 26 ) || m_turnovers[ 3 ][ 1 ] == ( offsets[ 3 ] % 26 ) )
		{
			offsets[ 2 ] = ( offsets[ 2 ] + 1 ) % 26;
		}
		else if ( m_turnovers[ 2 ][ 0 ] == ( offsets[ 2 ] % 26 ) || m_turnovers[ 2 ][ 1 ] == ( offsets[ 2 ] % 26 ) )
		{
			offsets[ 2 ] = ( offsets[ 2 ] + 1 ) % 26;
			offsets[ 1 ] = ( offsets[ 1 ] + 1 ) % 26;
		}

		offsets[ 3 ] = ( offsets[ 3 ] + 1 ) % 26;

		input = m_plugboard[ input - 'A' ];

		input = m_wheels[ 3 ][ ( input - 'A' + offsets[ 3 ] + 26 ) % 26 ];
		input = m_wheels[ 2 ][ ( input - 'A' + offsets[ 2 ] - offsets[ 3 ] + 26 ) % 26 ];
		input = m_wheels[ 1 ][ ( input - 'A' + offsets[ 1 ] - offsets[ 2 ] + 26 ) % 26 ];
		input = m_wheels[ 0 ][ ( input - 'A' + offsets[ 0 ] - offsets[ 1 ] + 26 ) % 26 ];

		input = m_reflector[ ( input - 'A' - offsets[ 0 ] + 26 ) % 26 ];

		input = m_reversed_wheels[ 0 ][ ( input - 'A' + offsets[ 0 ] + 26 ) % 26 ];
		input = m_reversed_wheels[ 1 ][ ( input - 'A' + offsets[ 1 ] - offsets[ 0 ] + 26 ) % 26 ];
		input = m_reversed_wheels[ 2 ][ ( input - 'A' + offsets[ 2 ] - offsets[ 1 ] + 26 ) % 26 ];
		input = m_reversed_wheels[ 3 ][ ( input - 'A' + offsets[ 3 ] - offsets[ 2 ] + 26 ) % 26 ];

		input = rotors::ETW[ ( input - 'A' - offsets[ 3 ] + 26 ) % 26 ];

		input = m_plugboard[ input - 'A' ];

		result += input;
	}
	return result;
}
