#ifndef IPTRAF_NG_TUI_MSGBOXES_H
#define IPTRAF_NG_TUI_MSGBOXES_H

#define ANYKEY_MSG "Press a key to continue"

void tx_init_error_attrs(int border, int text, int prompt);
void tx_init_info_attrs(int border, int text, int prompt);
void tx_infobox(char *text, char *prompt);

#endif	/* IPTRAF_NG_TUI_MSGBOXES_H */
