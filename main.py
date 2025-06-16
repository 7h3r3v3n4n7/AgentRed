#!/usr/bin/env python3
import sys
import os
from lib.App import App

def main():
    try:
        app = App()
        app.run()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()