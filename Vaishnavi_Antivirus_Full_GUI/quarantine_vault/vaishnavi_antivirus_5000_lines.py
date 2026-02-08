"""Compatibility shim: thin launcher delegating to modular package.

This file replaces the previous monolithic implementation with a
small compatibility layer that delegates to the new `vaishnavi_av`
package. Expand the modules under `vaishnavi_av/` rather than editing
this file for a maintainable codebase.
"""

import sys

def main():
    try:
        from vaishnavi_av import main as av_main
    except Exception as e:
        print("Failed to import modular package (vaishnavi_av):", e)
        sys.exit(1)

    av_main.run(sys.argv[1:])

if __name__ == "__main__":
    main()
