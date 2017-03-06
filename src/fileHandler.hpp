/** 
 *  @file		fileHandler.hpp
 *	@brief		Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *	@author		Jozef Zuzelka (xzuzel00)
 *	Mail:		xzuzel00@stud.fit.vutbr.cz
 *	Created:	06.03.2017 14:50
 *	Edited:		06.03.2017 15:21
 * 	Version:	1.0.0
 *	g++:		Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *	@bug
 *	@todo
 */

#pragma once

#include <fstream>      //  ofstream


void initOFile(std::ofstream &file);
void savePacket(std::ofstream &file);
