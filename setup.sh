sudo apt install git
sudo apt install golang-go
sudo apt install python3-pip
sudo apt install curl
sudo apt install jq
pip3 install httpie
pip3 install -r ./tools/requirements.txt
go get -u github.com/lc/gau
go get -u github.com/tomnomnom/httprobe
go get -u github.com/tomnomnom/assetfinder
go get -u github.com/tomnomnom/waybackurls
go get -v github.com/tomnomnom/anew@latest
go get -u github.com/tomnomnom/qsreplace
go install github.com/003random/getJS@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo chmod +x tools/*
export GOPATH=$HOME/go
sudo mkdir domain
