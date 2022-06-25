#include <array>
#include <string>
#include <string_view>

namespace enigma
{

	struct m4_machine
	{
		m4_machine();

		std::string decode( const std::string& message );

		std::array<std::string_view, 4> m_wheels;
		std::array<std::string, 4> m_reversed_wheels;
		std::array<int, 4> m_wheels_positions;
		std::array<int, 4> m_rings_settings;
		std::array<std::array<int, 2>, 4> m_turnovers;
		std::string_view m_reflector;
		std::array <char, 26> m_plugboard;
	};

}
