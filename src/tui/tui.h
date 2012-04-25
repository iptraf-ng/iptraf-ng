#ifndef IPTRAF_NG_TUI_TUI_H
#define IPTRAF_NG_TUI_TUI_H

#define ANYKEY_MSG "Press a key to continue"

extern void tui_error(const char *prompt, const char *err, ...) __attribute((format (printf, 2, 3)));
extern void tui_error_va(const char *prompt, const char *err, va_list vararg);

#endif	/* IPTRAF_NG_TUI_TUI_H */
