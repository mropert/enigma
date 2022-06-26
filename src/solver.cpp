#include "enigma/solver.h"

#include <iostream>
#include <stdexcept>

using namespace enigma;

m4_solver::settings
m4_solver::brute_force( std::string_view message, reflector reflector, std::span<const char* const> plugs, std::string_view plaintext )
{
	std::array<rotor, 4> wheels = { rotors[ 0 ], rotors[ 0 ], rotors[ 0 ], rotors[ 0 ] };

	// Leftmost rotor, beta or gamma
	for ( char left_idx = 9; left_idx <= 10; ++left_idx )
	{
		wheels[ 0 ] = rotors[ left_idx ];

		// Middle left rotor, I to VIII
		for ( char middle_left_index = 1; middle_left_index <= 8; ++middle_left_index )
		{
			wheels[ 1 ] = rotors[ middle_left_index ];
			// Middle right rotor, I to VIII
			for ( char middle_right_index = 1; middle_right_index <= 8; ++middle_right_index )
			{
				if ( middle_right_index == middle_left_index )
				{
					continue;
				}
				wheels[ 2 ] = rotors[ middle_right_index ];

				// Right rotor, I to VIII
				for ( char right_index = 1; right_index <= 8; ++right_index )
				{
					if ( right_index == middle_left_index || right_index == middle_right_index )
					{
						continue;
					}
					wheels[ 3 ] = rotors[ right_index ];

					for ( char middle_right_ring_setting = 0; middle_right_ring_setting < 26; ++middle_right_ring_setting )
					{
						for ( char right_ring_setting = 0; right_ring_setting < 26; ++right_ring_setting )
						{
							std::cout << "Trying rotors (" << int( left_idx ) << ", " << int( middle_left_index ) << ", "
									  << int( middle_right_index ) << ", " << int( right_index ) << "), settings (0, 0, "
									  << int( middle_right_ring_setting ) << ", " << int( right_ring_setting ) << ")" << std::endl;


							const auto key = brute_force_key( message,
															  wheels,
															  { 0, 0, middle_right_ring_setting, right_ring_setting },
															  reflector,
															  plugs,
															  plaintext );
							if ( !key.empty() )
							{
								return { { left_idx, middle_left_index, middle_right_index, right_index },
										 { 0, 0, middle_right_ring_setting, right_ring_setting },
										 key };
							}
						}
					}
				}
			}
		}
	}

	throw std::logic_error( "Should have matched" );
}


std::string m4_solver::brute_force_key( std::string_view message,
										const std::array<rotor, 4>& rotors,
										std::array<char, 4> ring_settings,
										reflector reflector,
										std::span<const char* const> plugs,
										std::string_view plaintext )
{
	std::string key = "AAAA";
	std::string result_buffer;

	const m4_machine machine( rotors, ring_settings, reflector, plugs );

	for ( int i = 0; i < 26; ++i )
	{
		key[ 0 ] = 'A' + i;
		for ( int j = 0; j < 26; ++j )
		{
			key[ 1 ] = 'A' + j;
			for ( int k = 0; k < 26; ++k )
			{
				key[ 2 ] = 'A' + k;
				for ( int l = 0; l < 26; ++l )
				{
					key[ 3 ] = 'A' + l;
					machine.decode( message, key, result_buffer );
					if ( result_buffer == plaintext )
					{
						return key;
					}
				}
			}
		}
	}

	return {};
}
