#include "enigma.h"

using enigma::m4_machine;
using enigma::rotor;

m4_machine::m4_machine( const std::array<rotor, 4>& rotors,
						std::array<char, 4> ring_settings,
						reflector reflector,
						std::span<const char* const> plugs )
	: m_rotors( rotors )
	, m_rings_settings( ring_settings )
	, m_reflector( reflector )
{
	for ( int i = 0; i < 4; ++i )
	{
		for ( int j = 0; j < 2; ++j )
		{
			if ( m_rotors[ i ].m_turnovers[ j ] != -1 )
			{
				m_rotors[ i ].m_turnovers[ j ] = ( m_rotors[ i ].m_turnovers[ j ] + 26 - m_rings_settings[ i ] ) % 26;
			}
		}
	}

	for ( int i = 0; i < m_plugboard.size(); ++i )
	{
		m_plugboard[ i ] = 'A' + i;
	}

	for ( auto pair : plugs )
	{
		m_plugboard[ pair[ 0 ] - 'A' ] = pair[ 1 ];
		m_plugboard[ pair[ 1 ] - 'A' ] = pair[ 0 ];
	}
}

std::string m4_machine::decode( std::string_view message, std::string_view key )
{
	std::string result;
	result.reserve( message.size() );

	const std::array<char, 4> start_positions = { key[ 0 ] - 'A', key[ 1 ] - 'A', key[ 2 ] - 'A', key[ 3 ] - 'A' };

	std::array<int, 4> offsets = { start_positions[ 0 ] - m_rings_settings[ 0 ],
								   start_positions[ 1 ] - m_rings_settings[ 1 ],
								   start_positions[ 2 ] - m_rings_settings[ 2 ],
								   start_positions[ 3 ] - m_rings_settings[ 3 ] };

	for ( const auto character : message )
	{
		char input = character;

		if ( m_rotors[ 3 ].m_turnovers[ 0 ] == ( offsets[ 3 ] % 26 ) || m_rotors[ 3 ].m_turnovers[ 1 ] == ( offsets[ 3 ] % 26 ) )
		{
			offsets[ 2 ] = ( offsets[ 2 ] + 1 ) % 26;
		}
		else if ( m_rotors[ 2 ].m_turnovers[ 0 ] == ( offsets[ 2 ] % 26 ) || m_rotors[ 2 ].m_turnovers[ 1 ] == ( offsets[ 2 ] % 26 ) )
		{
			offsets[ 2 ] = ( offsets[ 2 ] + 1 ) % 26;
			offsets[ 1 ] = ( offsets[ 1 ] + 1 ) % 26;
		}

		offsets[ 3 ] = ( offsets[ 3 ] + 1 ) % 26;

		input = m_plugboard[ input - 'A' ];

		input = m_rotors[ 3 ].m_wiring[ input - 'A' + offsets[ 3 ] + 26 ];
		input = m_rotors[ 2 ].m_wiring[ input - 'A' + offsets[ 2 ] - offsets[ 3 ] + 26 ];
		input = m_rotors[ 1 ].m_wiring[ input - 'A' + offsets[ 1 ] - offsets[ 2 ] + 26 ];
		input = m_rotors[ 0 ].m_wiring[ input - 'A' + offsets[ 0 ] - offsets[ 1 ] + 26 ];

		input = m_reflector.m_wiring[ input - 'A' - offsets[ 0 ] + 26 ];

		input = m_rotors[ 0 ].m_reversed_wiring[ input - 'A' + offsets[ 0 ] + 26 ];
		input = m_rotors[ 1 ].m_reversed_wiring[ input - 'A' + offsets[ 1 ] - offsets[ 0 ] + 26 ];
		input = m_rotors[ 2 ].m_reversed_wiring[ input - 'A' + offsets[ 2 ] - offsets[ 1 ] + 26 ];
		input = m_rotors[ 3 ].m_reversed_wiring[ input - 'A' + offsets[ 3 ] - offsets[ 2 ] + 26 ];

		input = enigma::rotors[ static_cast<int>( enigma::rotor_index::ETW ) ].m_wiring[ input - 'A' - offsets[ 3 ] + 26 ];

		input = m_plugboard[ input - 'A' ];

		result += input;
	}
	return result;
}
