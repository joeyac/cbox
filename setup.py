from distutils.core import setup, Extension

cbox_module = Extension('cbox', sources=['cbox.c', 'main.c'])

setup(name='cbox',
      version='1.1',
      description='this is a demo',
      ext_modules=[cbox_module])
