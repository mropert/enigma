#include "enigma/solver.h"

#include <atomic>
#include <execution>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace enigma;

namespace
{
	std::vector<std::array<int, 4>> generate_rotor_combinations()
	{
		std::vector<std::array<int, 4>> combinations;
		combinations.reserve( 2 * 8 * 7 * 6 );

		// Leftmost rotor, beta or gamma
		for ( int left_idx = 9; left_idx <= 10; ++left_idx )
		{
			// Middle left rotor, I to VIII
			for ( int middle_left_index = 1; middle_left_index <= 8; ++middle_left_index )
			{
				// Middle right rotor, I to VIII
				for ( int middle_right_index = 1; middle_right_index <= 8; ++middle_right_index )
				{
					if ( middle_right_index == middle_left_index )
					{
						continue;
					}

					for ( int right_index = 1; right_index <= 8; ++right_index )
					{
						if ( right_index == middle_left_index || right_index == middle_right_index )
						{
							continue;
						}

						combinations.emplace_back( std::array<int, 4> { left_idx, middle_left_index, middle_right_index, right_index } );
					}
				}
			}
		}

		return combinations;
	}
}

template <typename score_type, typename validate_type>
std::optional<m4_solver::settings> fine_tune_key( std::string_view message,
												  const m4_solver::settings& settings,
												  reflector reflector,
												  std::span<const char* const> plugs,
												  const score_type& score,
												  const validate_type& validate )
{
	const std::array<rotor, 4> wheels = { rotors[ settings.m_rotors[ 0 ] ],
										  rotors[ settings.m_rotors[ 1 ] ],
										  rotors[ settings.m_rotors[ 2 ] ],
										  rotors[ settings.m_rotors[ 3 ] ] };
	std::string key = settings.m_key;
	std::string buffer;
	buffer.reserve( message.size() );

	// Adjust rings (and corresponding key) from right to left (as getting right correct first will improve score)
	std::array<std::size_t, 26> scores = {};
	for ( char right_ring = 0; right_ring < 26; ++right_ring )
	{
		key[ 3 ] = ( settings.m_key[ 3 ] - 'A' + right_ring - settings.m_ring_settings[ 3 ] + 26 ) % 26 + 'A';
		const m4_machine machine( wheels, { 0, 0, settings.m_ring_settings[ 2 ], right_ring }, reflector, plugs );
		machine.decode( message, key, buffer );
		scores[ right_ring ] = score( buffer );
	}

	const char best_right = std::distance( begin( scores ), std::max_element( begin( scores ), end( scores ) ) );
	key[ 3 ] = ( settings.m_key[ 3 ] - 'A' + best_right - settings.m_ring_settings[ 3 ] + 26 ) % 26 + 'A';

	// Then middle right
	for ( char middle_right_ring = 0; middle_right_ring < 26; ++middle_right_ring )
	{
		key[ 2 ] = ( settings.m_key[ 2 ] - 'A' + middle_right_ring - settings.m_ring_settings[ 2 ] + 26 ) % 26 + 'A';

		const m4_machine machine( wheels, { 0, 0, middle_right_ring, best_right }, reflector, plugs );
		machine.decode( message, key, buffer );
		if ( validate( buffer ) )
		{
			auto final_settings = settings;
			final_settings.m_ring_settings[ 2 ] = middle_right_ring;
			final_settings.m_ring_settings[ 3 ] = best_right;
			final_settings.m_key = key;
			return final_settings;
		}
	}

	return {};
}

template <typename heuristic_type>
std::vector<std::string> brute_force_key( std::string_view message, const m4_machine& machine, const heuristic_type& match )
{
	std::vector<std::string> matches;
	std::string key = "AAAA";
	std::string result_buffer;

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
					if ( match( result_buffer ) )
					{
						matches.emplace_back( key );
					}
				}
			}
		}
	}

	return matches;
}

template <typename heuristic_type, typename score_type, typename validate_type>
std::optional<m4_solver::settings> crack_settings( std::string_view message,
												   reflector reflector,
												   std::span<const char* const> plugs,
												   const heuristic_type& heuristic,
												   const score_type& score,
												   const validate_type& validate,
												   m4_solver::progress_fn progress_update )
{
	using m4_solver::settings;

	std::atomic<std::size_t> progress = 0;
	std::atomic<std::size_t> false_positives = 0;
	const std::size_t total = std::size_t( 2 ) * 8 * 7 * 6 * 26 * 26 * 26 * 26;

	static const auto rotor_combinations = generate_rotor_combinations();

	const auto root_thread_id = std::this_thread::get_id();
	settings found_settings;
	std::atomic_bool found = false;

	std::for_each( std::execution::par_unseq,
				   begin( rotor_combinations ),
				   end( rotor_combinations ),
				   [ & ]( const std::array<int, 4>& rotor_settings ) {
					   const std::array<rotor, 4> wheels = { rotors[ rotor_settings[ 0 ] ],
															 rotors[ rotor_settings[ 1 ] ],
															 rotors[ rotor_settings[ 2 ] ],
															 rotors[ rotor_settings[ 3 ] ] };

					   const m4_machine machine( wheels, { 0, 0, 0, 0 }, reflector, plugs );

					   const auto keys = brute_force_key( message, machine, heuristic );
					   if ( !keys.empty() )
					   {
						   settings potential_settings { rotor_settings, { 0, 0, 0, 0 }, "AAAA" };

						   for ( const auto& key : keys )
						   {
							   potential_settings.m_key = key;
							   const auto settings = fine_tune_key( message, potential_settings, reflector, plugs, score, validate );
							   if ( settings )
							   {
								   found = true;
								   found_settings = *settings;
								   return;
							   }
						   }

						   false_positives += keys.size();
					   }

					   if ( found )
					   {
						   return;
					   }

					   progress += 26 * 26 * 26 * 26;
					   if ( progress_update && root_thread_id == std::this_thread::get_id() )
					   {
						   progress_update( progress, total, false_positives );
					   }
				   } );

	if ( found )
	{
		return found_settings;
	}

	return std::nullopt;
}



std::optional<m4_solver::settings> m4_solver::crack_settings( std::string_view message,
															  reflector reflector,
															  std::span<const char* const> plugs,
															  std::string_view plaintext,
															  progress_fn progress )
{
	const auto validate = [ plaintext ]( std::string_view candidate ) { return candidate == plaintext; };

	if ( plugs.empty() )
	{
		const auto match_heuristic = [ plaintext, score = plaintext.size() / 10 ]( std::string_view candidate ) {
			return unknown_plugboard_match_score( plaintext, candidate ) >= score;
		};
		const auto score = [ plaintext ]( std::string_view candidate ) { return unknown_plugboard_match_score( plaintext, candidate ); };

		return ::crack_settings( message, reflector, plugs, match_heuristic, score, validate, std::move( progress ) );
	}
	else
	{
		const auto target_score = partial_match_reference_score( message.size() );
		const auto match_heuristic = [ plaintext, target_score ]( std::string_view candidate ) {
			return partial_match_score( plaintext, candidate ) >= target_score;
		};
		const auto score = [ plaintext ]( std::string_view candidate ) { return partial_match_score( plaintext, candidate ); };

		return ::crack_settings( message, reflector, plugs, match_heuristic, score, validate, std::move( progress ) );
	}
}

std::optional<m4_solver::settings> m4_solver::crack_settings_with_crib( std::string_view message,
																		reflector reflector,
																		std::span<const char* const> plugs,
																		std::string_view crib,
																		std::span<const size_t> crib_locations,
																		progress_fn progress )
{
	const auto score = [ crib, crib_locations ]( std::string_view candidate ) {
		std::size_t best_score = 0;
		for ( const auto location : crib_locations )
		{
			const auto score = partial_match_score( crib, candidate.substr( location, crib.size() ) );
			if ( score > best_score )
			{
				best_score = score;
			}
		}
		return best_score;
	};
	const auto target_score = partial_match_reference_score( crib.size() );
	const auto match_heuristic = [ score, target_score ]( std::string_view candidate ) { return score( candidate ) >= target_score; };
	const auto validate = [ crib ]( std::string_view candidate ) { return candidate.contains( crib ); };

	return ::crack_settings( message, reflector, plugs, match_heuristic, score, validate, std::move( progress ) );
}


std::optional<m4_solver::settings> m4_solver::fine_tune_key( std::string_view message,
															 const settings& settings,
															 reflector reflector,
															 std::span<const char* const> plugs,
															 std::string_view plaintext )
{
	const auto score = [ plaintext ]( std::string_view candidate ) { return partial_match_score( plaintext, candidate ); };
	const auto validate = [ plaintext ]( std::string_view candidate ) { return candidate == plaintext; };

	return ::fine_tune_key( message, settings, reflector, plugs, score, validate );
}

std::vector<std::string> m4_solver::crack_key( std::string_view message,
											   const std::array<rotor, 4>& rotors,
											   const std::array<int, 4> ring_settings,
											   reflector reflector,
											   std::span<const char* const> plugs,
											   std::string_view plaintext )
{
	const auto target_score = partial_match_reference_score( message.size() );
	const auto match_heuristic = [ plaintext, target_score ]( std::string_view candidate ) {
		return partial_match_score( plaintext, candidate ) >= target_score;
	};

	const m4_machine machine( rotors, ring_settings, reflector, plugs );
	return brute_force_key( message, machine, match_heuristic );
}

namespace
{
	bool can_contain_crib( std::string_view cyphertext, std::string_view crib )
	{
		for ( int i = 0; i < crib.size(); ++i )
		{
			if ( cyphertext[ i ] == crib[ i ] )
			{
				return false; // Enigma can never encode a plaintext letter to itself
			}
		}
		return true;
	}
}

std::vector<std::size_t> enigma::find_potential_crib_location( std::string_view cyphertext, std::string_view crib )
{
	std::vector<std::size_t> locations;

	for ( int i = 0; i + crib.size() <= cyphertext.size(); ++i )
	{
		if ( can_contain_crib( cyphertext.substr( i ), crib ) )
		{
			locations.emplace_back( i );
		}
	}

	return locations;
}
