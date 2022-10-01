# Yara build instructions for Ubuntu
1. sudo apt-get install automake libtool make gcc pkg-config git libssl-dev
2. git clone https://github.com/VirusTotal/yara
3. cd yara && ./bootstrap.sh && ./configure && make
4. sudo make install && sudo ldconfig
