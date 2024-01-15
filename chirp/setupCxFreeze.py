from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
build_options = {
    'packages': ['chirp.drivers'], 
    'excludes': []
    }

import sys
base = 'Win32GUI' if sys.platform=='win32' else None

executables = [
    Executable('chirpwx.py', base=base, target_name = 'CHIRP_egzumer', icon = 'chirp/share/chirp.ico')
]

setup(name='CHIRP egzumer',
      version = '0.1',
      description = 'modfied CHIRP with UV-K5 egzumer firmware driver',
      options = {'build_exe': build_options},
      executables = executables)

