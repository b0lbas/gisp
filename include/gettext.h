/* gettext.h -- convenience header for message translation.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* The whole translation layer is optional: with ENABLE_NLS the program is
   linked against GNU gettext, otherwise every macro below collapses to a
   no-op so the same sources build unchanged without libintl.  */

#ifndef GISP_GETTEXT_H
#define GISP_GETTEXT_H 1

#if defined ENABLE_NLS && ENABLE_NLS

# include <libintl.h>

#else

/* No NLS: define just enough of the libintl interface to keep the call
   sites unchanged.  */
# undef gettext
# define gettext(Msgid) ((const char *) (Msgid))
# undef textdomain
# define textdomain(Domainname) ((void) (Domainname))
# undef bindtextdomain
# define bindtextdomain(Domainname, Dirname) ((void) (Dirname))

#endif

/* _() marks strings for translation and translates them at run time.
   N_() only marks them (for strings translated later or elsewhere).  */
#undef _
#define _(String) gettext (String)

#undef N_
#define N_(String) (String)

#endif /* GISP_GETTEXT_H */
