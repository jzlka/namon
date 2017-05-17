/** 
 *  @file       fileHandler.hpp
 *  @brief      File handler header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 06.03.2017 14:50
 *   - Edited:  18.05.2017 00:14
 */

#pragma once

#include <fstream>              //  ofstream




namespace TOOL
{


/*!
 * @brief       Creates the output file and writes SectionHeaderBlock and InterfaceDescriptionBlock to the file
 * @param[in]   oFile   The output file
 * @return      Zero if initialization was successful. True otherwise
 */
int initOFile(std::ofstream & oFile);


}	// namespace TOOL
