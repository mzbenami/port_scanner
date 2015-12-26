from setuptools import find_packages, setup

setup(name='port_scanner',
      version='0.0.1',
      packages=find_packages(),
      entry_points={
        'console_scripts': [
            'port-scanner=portscanner:main'
        ]
      },
)
