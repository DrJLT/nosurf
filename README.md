# nosurf

This is a stripped-down version of the nosurf package by justinas. I do not recommend it for use without understanding the code.

Please note that we're looking for the token in a field in the header of the html named "CSRF". It cannot be placed in the body (but can easily be modified to do so, per the original package). Most features have be stripped away to make this faster.

All credits go to the original authors.

Please beware that http.Cookie is set for secure ONLY.