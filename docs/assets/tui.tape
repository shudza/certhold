# VHS tape for the README TUI demo — render with `vhs docs/assets/tui.tape`
# from the repo root (https://github.com/charmbracelet/vhs).
#
# Prerequisites: `certhold` on PATH, a populated fleet in the default data dir
# (~/.certhold), and `certhold serve` running so the Status view reads healthy.
# The recorded fleet was staged with real enrollments into dockerized peers
# (alpine + sshd), so every view shows live state.

Output docs/assets/tui.gif

Set FontSize 15
Set Width 1200
Set Height 680
Set Padding 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Hide
Type "export PATH=/workspace/bin:$PATH && clear"
Enter
Show

Type "certhold tui"
Sleep 600ms
Enter
Sleep 2s

Type "j"
Sleep 300ms
Type "j"
Sleep 300ms
Type "j"
Sleep 500ms
Enter
Sleep 2.5s
Escape
Sleep 600ms

Type "2"
Sleep 1s
Type "j"
Sleep 1.5s

Type "3"
Sleep 2.5s

Type "4"
Sleep 500ms
Type "P"
Sleep 3s

Type "q"
Sleep 500ms
