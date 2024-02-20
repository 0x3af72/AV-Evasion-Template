#include <iostream>

#include "include/skCrypter.h"

#pragma once

#define SKC(a) ((std::string) skCrypt(a))
#define SKCC(a) ((char*) skCrypt(a))
#define SKCR(a) (skCrypt(a))