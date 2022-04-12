sudo apt install git
sudo apt install golang-go
sudo apt install python3-pip
sudo apt install curl
sudo apt install jq
pip install httpie
pip3 install -r ./tools/requirements.txt
go install github.com/hahwul/dalfox/v2@latest
chmod +x tools/*
export GOPATH=$HOME/go
mkdir domain
