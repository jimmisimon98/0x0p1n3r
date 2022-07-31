#!/bin/bash
#Coded-by Jimmi Simon
#version=v1.6



checkrequirements(){
	
			
			
	if [ ! -f $GOPATH/bin/assetfinder ]; then
		echo "assettfinder is missing. please install it";
		exit;
	fi
	
	if [ ! -f $GOPATH/bin/gau ]; then	
		echo "gau is missing. please install it";
		exit;
	fi
	
	if [ ! -f  tools/knock/knockpy/knockpy.py ]; then
		echo "knockpy is missing. please install it";
		exit
	fi
	
	if [ ! -f tools/Sublist3r/sublist3r.py ]; then
		echo "sublist3r is missing. please install it";
		exit;
	fi
			
	if [ ! -f $GOPATH/bin/httpx ]; then
		echo "httpx is missing. please install it";
		exit;
	fi
	
	if [ ! -f $GOPATH/bin/httprobe ]; then
		echo "httprobe is missing. please install it";
		exit;
	fi
	if [ ! -f $pwd/tools/ipaddress.py ]; then
		echo "ipaddress.py is missing. please install it";
		exit;
	fi
	
	if [ ! -f $pwd/tools/subcheck.go ]; then
		echo "subcheck.go is missing. please install it";
		exit;
	fi
	
	if [ ! -f tools/takeover/takeover.py ]; then
		echo "takeover.py is missing. please install it";
		exit;
	fi
	
	if [ ! -f $GOPATH/bin/waybackurls ]; then
		echo "waybackurls is missing. please install it";
		exit;
	fi
	
	if [ ! -f $GOPATH/bin/qsreplace ]; then
		echo "qsreplace is missing. please install it";
		exit;
	fi
	
	if [ ! -f $GOPATH/bin/anew ]; then
		echo "anew is missing. please install it";
		exit;
	fi
	
	if [ ! -f $pwd/tools/kxss.go ]; then
		echo "kxss is missing. please install it";
		exit;
	fi
	
	if [ ! -f $GOPATH/bin/nuclei ]; then
		echo "nuclei is missing. please install it";
		exit;
	fi

}
subdomainscan(){
	
	

	if [[ -d $pwd/domain/$domain ]];
	then
		rm -r $pwd/domain/$domain
	fi

			

	printf "\nDomain is $domain , Searching for Subdomains"	
	printf "\nThis may take a while...\n"
			

			
	## checking subdomains 
	if [ -f temp.txt ]; then
		sudo rm temp.txt
	fi
	if [ -f $domain ]; then
	   	sudo rm $domain
	fi
	if [ -f $domain"new" ]; then
		sudo rm $domain"new"
	fi

	mkdir $pwd/domain/$domain
	echo "5% completed..."
	sub1=`$GOPATH/bin/assetfinder --subs-only $domain | sort -u | tr " " "\n" >> temp.txt`
	echo "10% completed..."
	sub2=`$GOPATH/bin/gau --subs $domain | cut -d / -f 3 | cut -d ":" -f1 | tr " " "\n" | sort -u >> temp.txt`
	echo "15% completed..."
	sub3=`python3 tools/knock/knockpy/knockpy.py $domain | cut -d "," -f1  | tr "]" " "| tr '"' " " | tr "[" " "  | cut -d " " -f6 >>temp.txt`
	echo "40% completed..."
	sub7=`curl -X GET -A "Mozilla/5.0" -k -s -L "https://crt.sh/?q=%25.$domain&output=json" | jq -r .[].name_value | sed 's/\*\.//g' | $GOPATH/bin/httpx -title -silent | $GOPATH/bin/anew | cut -d " " -f1 | sort -u >> temp.txt`
	echo "50% completed..."
	sub8=`curl -X GET -A "Mozilla/5.0" -k -s -L "https://dns.bufferover.run/dns?q=.$domain" | jq -r .FDNS_A[] |cut -d "," -f2|sort -u >> temp.txt`
	echo "55% completed..."
	sub9=`curl -X GET -A "Mozilla/5.0" -k -s -L "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >>temp.txt`
	echo "60% completed..."
	sub10=`curl -X GET -A "Mozilla/5.0" -k -s -L "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | cut -d ":" -f1 | sort -u >> temp.txt`
	echo "70% completed..."
	sub11=`curl -X GET -A "Mozilla/5.0" -k -s -L 'https://securitytrails.com/list/apex_domain/$domain' | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | grep '.$domain' | sort -u >> temp.txt`
	echo "75% completed..."
	sub12=`curl -X GET -A "Mozilla/5.0" -k -s -L "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq -r .subdomains[] >> temp.txt`
	echo "80% completed..."
	sub13=`curl -X GET -A "Mozilla/5.0" -k -s -L "https://api.hackertarget.com/hostsearch/?q=$domain" | cut -d "," -f1 >> temp.txt`
	echo "85% completed..."
	sub14=`curl -X GET -A "Mozilla/5.0" -k -s -L "https://sonar.omnisint.io/subdomains/$domain" | grep "$domain" | sed 's/"//g' | sed 's/,/\n/g' | sed 's/[][]//g' | sort -u >> temp.txt`
	sub15=`curl -X GET -A "Mozilla/5.0" -k -s "https://api.shodan.io/dns/domain/$domain?key=$SHODAN_API_KEY" -s| jq -r .subdomains[] | sed -e 's/$/.'$domain'/' >> temp.txt`
	echo "90% completed..."
	sub4=`python3 tools/Sublist3r/sublist3r.py -t 500 -d $domain -n >> temp.txt`
	echo "subdomain enumeration completed.."
				
				
	sort -u temp.txt | grep "$domain"> $domain
	sudo rm temp.txt
	
	cp $domain $pwd/domain/$domain/$domain"_without_httpx"
		
	echo "checking live sub-domains.."
	fin=`cat $domain | $GOPATH/bin/httprobe  >> $domain"new"`
			

	## sorting URLS
	echo "sorting..."
	sort -u $domain"new" > $pwd/domain/$domain/$domain
	cat $pwd/domain/$domain/$domain | cut -d "/" -f3 | sort -u >> $pwd/domain/$domain/$domain"_domain"
	echo "100% completed"
	sudo rm $domain"new";
	sudo rm $domain
	printf "\n ${Green}Result Saved in $pwd/domain/$domain/$domain ${NC}\n\n";
			
				


	## checking subdomain takeover
	
	printf "\nChecking for subdomain takeover,This may take a while...\n"
	while read line; 
	do
		go run $pwd/tools/subcheck.go $line >> takeover.txt
	done < $pwd/domain/$domain/$domain
	echo "Takeover checking 1 completed"
	python3 tools/takeover/takeover.py -l $pwd/domain/$domain/$domain >> takeover.txt
	echo "Takeover checking 2 completed"
	NtHiM -f $pwd/domain/$domain/$domain >> takeover.txt
	echo "Takeover checking 3 completed";
	sort -u takeover.txt >> $pwd/domain/$domain/$domain"_subdomain_takeover"
	rm takeover.txt
			
	$GOPATH/bin/dnsx -l $pwd/domain/$domain/$domain"_subdomain_takeover" -silent -resp -a -aaaa -cname -mx -ns -soa -txt > $pwd/domain/$domain/$domain"_subdomain_takeover_dnsx.txt"
	printf "\nChecking subdomain takeover completed\n"
			
			
	
	
	printf "\n\n ${Green} all details are saved in domain/$domain folder${NC}";
}
internalchecking(){
	## Checking internal errors
	echo "checking internal error"
	if [ ! -z $proxy ];
	then
		cat $pwd/domain/$domain/$domain"_domain" | $GOPATH/bin/httpx -silent -sc -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -proxy $proxy | grep "500" >> $pwd/domain/$domain/$domain"_internal_error.txt"
	else
		cat $pwd/domain/$domain/$domain"_domain" | $GOPATH/bin/httpx -silent -sc -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | grep "500" >> $pwd/domain/$domain/$domain"_internal_error.txt"
	fi
	echo "Internal error checking completed"

}

crlfscan(){

	## Checking CRLF
	crlfsuite -i $pwd/domain/$domain/$domain
}

brokenlinkscan(){
	## Broken link hijacking
	echo "checking broken links";
	if [ -f broken_link_check.txt ];
	then
		sudo rm broken_link_check.txt
	fi
			
	cat $pwd/domain/$domain/$domain | $GOPATH/bin/hakrawler -u  >> $pwd/domain/$domain/$domain"_broken_link_check.txt"
	cat $pwd/domain/$domain/$domain"_broken_link_check.txt" | grep -v '$domain' | $GOPATH/bin/httpx -silent -sc | grep -v 200 | >> $pwd/domain/$domain/$domain"_broken_links.txt"
	echo "broken link checking completed"
}

parametersscan(){
	### parameter
	echo "checking parameters"
	cat $pwd/domain/$domain/$domain"_domain" | $GOPATH/bin/gau | grep "=" >> $pwd/domain/$domain/$domain"_all_parameters.txt"		
	cat $pwd/domain/$domain/$domain"_domain" | $GOPATH/bin/waybackurls | grep "=" >> $pwd/domain/$domain/$domain"_all_parameters.txt"
	cat $pwd/domain/$domain/$domain"_all_parameters.txt" | sed '/\.css/d' | sed '/\.js/d' | sed '/\.svg/d' | sed '/\.png/d' | sed '/\.jpg/d' | sed '/\.woff/d' | sed '/\.txt/d' | grep "$domain" | sort -u >>  $pwd/domain/$domain/$domain"_parameters"
	

	alldics=`cat $pwd/domain/$domain/$domain >> alldics.txt`
	alldics1=`cat $pwd/domain/$domain/$domain"_all_parameters.txt" | cut -d "?" -f1 | sed "/\.js/d" | sed "/\.cs/d" | sort -u >> alldics.txt`
	cat alldics.txt | sort | uniq -u >> $pwd/domain/$domain/$domain"_all_dictionaries"
	rm alldics.txt
	echo "parameter checking completed"
	
}
graphqlscan(){



	## GraphQl check
	echo "checking GraphQl path"
	if [ ! -z $proxy ];
	then
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /graphql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /graphiql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /console/graphql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /console/graphiql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /gql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
	else
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -silent -path /graphql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -silent -path /graphiql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -silent -path /console/graphql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -silent -path /console/graphiql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -silent -path /gql/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_graphql.txt"
	fi
	echo "checking GraphQl path completed"

	
}
cvescans(){
	###spring4shell
	echo "spring4shell checking"
	bash $pwd/tools/CVE/CVE-2022-22965.sh $pwd/domain/$domain/$domain"_all_dictionaries"
	echo "CVE-2022-33891 checking"
	if [ ! -z $burp ];
	then
		python $pwd/tools/CVE/cve_2022_33891_poc.py -f $pwd/domain/$domain/$domain"_all_dictionaries" -d $burp
	else
		python $pwd/tools/CVE/cve_2022_33891_poc.py -f $pwd/domain/$domain/$domain"_all_dictionaries" 
	fi
	echo "CVE-2022-26134 checking"
	python $pwd/tools/CVE/CVE-2022-26134.py -f $pwd/domain/$domain/$domain"_all_dictionaries" -c id -o $domain"_cve-2022-26134" 
	
	echo "Log4j checking"
	cd $pwd/tools/CVE/log4j-scan/
	python log4j-scan.py --run-all-tests --waf-bypass -l $pwd/domain/$domain/$domain 
	cd ../../	


}
sourcecodescan(){
	
	###.git
	echo "checking source-code "
	if [ ! -z $proxy ];
	then
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /.git/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /.svn/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /.hg/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /.bzr/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /.env/ -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /application/configs/application.ini -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /storage/logs/laravel.log -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain"_all_dictionaries" | $GOPATH/bin/httpx -proxy $proxy -silent -path /wp-content/debug.log -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
	else
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /.git/config -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /.svn/entries -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /.hg/hgrc -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /.bzr/branch/branch.conf -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /.env -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /application/configs/application.ini -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /storage/logs/laravel.log -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
		cat $pwd/domain/$domain/$domain | $GOPATH/bin/httpx  -silent -path /wp-content/debug.log -content-length -status-code  -ports 80,443,4443,8000,8008,8009,8080,8081,8090,8443,8888 -threads 100 -title | $GOPATH/bin/anew >> $pwd/domain/$domain/$domain"_source_code"
	fi
	sort -u $pwd/domain/$domain/$domain"_source_code" >> $pwd/domain/$domain/$domain"_source_code_details"
	rm $pwd/domain/$domain/$domain"_source_code"
	echo "source-code checking completed"
	
}

javascriptfilesscan(){
	### js files
	if [ -f jsfiles.txt ]; 
	then
		sudo rm jsfiles.txt
	fi
	echo "checking js secrets"
	cat $pwd/domain/$domain/$domain"_all_parameters.txt" | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> jsfiles.txt
	cat $pwd/domain/$domain/$domain"_domain" | $GOPATH/bin/getJS --insecure --complete | grep "$domain" >> jsfiles.txt
	cat jsfiles.txt | awk -F"?" '{print $1}' | grep '.js' | sort -u >> $pwd/domain/$domain/$domain"_js_files"
	rm jsfiles.txt
	cd $pwd/tools/SecretFinder
	while read line;
	do
		python3 SecretFinder.py -i $line -o cli >> $pwd/domain/$domain/$domain"_js_secret_check"
	done < $pwd/domain/$domain/$domain"_js_files"
	cd ../../
	echo "checking js secrets completed"

}

ssrfscan(){
	### ssrf
	if [ -f ssrf.txt ]; 
	then
		sudo rm ssrf.txt
	fi
	echo "checking ssrf"
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=http" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=sftp" >> ssrf.txt	
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=tftp" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=file" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=ldap" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=netdoc" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=jar" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=dict" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=gopher" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "=netdoc" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "forward=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "dest=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "redirect=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "uri=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "path=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "continue=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "url=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "window=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "to=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "out=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "view=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "dir=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "show=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "navigation=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "file=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "val=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "validate=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "domain=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "callback=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "return=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "page=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "feed=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "host=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "port=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "next=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "data=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "reference=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "site=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "html=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "document=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "folder=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "root=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "pg=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "style=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "pdf=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "template=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "php=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "img=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "image=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "template=" >> ssrf.txt
	cat $pwd/domain/$domain/$domain"_parameters" | grep "doc=" >> ssrf.txt
				
			
	cat ssrf.txt | sort | uniq -u  >> $pwd/domain/$domain/$domain"_ssrf_manual_check"
	rm ssrf.txt
			
	if [ ! -z $burp ];
	then
	
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace $burp | $GOPATH/bin/httpx  -silent -threads 100 
	
	fi
			
	echo "ssrf checking completed"
	
}
xssscan(){
	
	### xss
	echo "checking xss"
	cat $pwd/domain/$domain/$domain"_parameters" | go run $pwd/tools/kxss.go >> $pwd/domain/$domain/$domain"_kxss"
	cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/Gxss -c 1000 >> $pwd/domain/$domain/$domain"_check_xss"
	$GOPATH/bin/dalfox file $pwd/domain/$domain/$domain"_parameters"

	echo "xss checking completed"
	
}
sqlscan(){
	### SQL
	echo "checking sql"
	if [ ! -z $proxy ];
	then
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'mysql' -threads 10 >> sqlcheck.txt
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'syntax' -threads 10 >> sqlcheck.txt
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'Error' -threads 10 >> sqlcheck.txt
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'SQL' -threads 10 >> sqlcheck.txt
	else
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx  -silent -match-regex 'mysql' -threads 10 >> sqlcheck.txt
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx  -silent -match-regex 'syntax' -threads 10 >> sqlcheck.txt
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx  -silent -match-regex 'Error' -threads 10 >> sqlcheck.txt
		cat $pwd/domain/$domain/$domain"_parameters" | $GOPATH/bin/qsreplace '\'  | $GOPATH/bin/httpx  -silent -match-regex 'SQL' -threads 10 >> sqlcheck.txt
	fi
	cat sqlcheck.txt | sort | uniq -u  >> $pwd/domain/$domain/$domain"_sql_vulnerable"
	rm sqlcheck.txt
	echo "sql checking completed"
}
sstiscan(){
	
	### SSTI
	echo "checking ssti"
	if [ ! -z $proxy ];
	then
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi{{7*7}}'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi${{7*7}}'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi${7*7}'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi${7*7}' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi<%= 7*7 %>'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi@(7*7)'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi#{7*7}'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi${7*7}'  | $GOPATH/bin/httpx -proxy $proxy -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
	else
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi{{7*7}}'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi${{7*7}}'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi${7*7}'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi${7*7}' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi<%= 7*7 %>'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi@(7*7)'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi#{7*7}'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
		cat $pwd/domain/$domain/$domain"_check_xss" | $GOPATH/bin/qsreplace 'jimmi${7*7}'  | $GOPATH/bin/httpx  -silent -match-regex 'jimmi49' -threads 10 >> ssti.txt
	fi
	
	cat ssti.txt | sort | uniq -u  >> $pwd/domain/$domain/$domain"_ssti_vulnerable"
	rm ssti.txt
	echo "ssti checking completed"
	
	
}


nucleiscan(){
	

	### nuclie
	echo "updating $GOPATH/bin/nuclei"
	$GOPATH/bin/nuclei -update
	$GOPATH/bin/nuclei -update-templates
	echo "update completed"




	echo "checking with $GOPATH/bin/nuclei"
	cat $pwd/domain/$domain/$domain >> $pwd/domain/$domain/$domain"_nuclie"
	cat $pwd/domain/$domain/$domain"_parameters" >> $pwd/domain/$domain/$domain"_nuclie"
	sort -u $pwd/domain/$domain/$domain"_nuclie" >> $pwd/domain/$domain/$domain"_nuclie_final"

	if [ ! -z $burp ];
	then

		$GOPATH/bin/nuclei -c 100 -l $pwd/domain/$domain/$domain"_nuclie_final" -t "/root/.local/nuclei-templates" -silent -iserver $burp
	else
		$GOPATH/bin/nuclei -c 100 -l $pwd/domain/$domain/$domain"_nuclie_final" -t "/root/.local/nuclei-templates" -silent
	fi

}
ipscan(){

	echo "Collecting IP address "
	echo $domain| uncover -e shodan,censys,fofa -silent >> temp.txt
	echo 'ssl:"'$domain'"'| uncover -e shodan,censys,fofa -silent >> temp.txt
	cat temp.txt | sort | uniq -u >> $pwd/domain/$domain/$domain"_ip_scanning_uncover"
	rm temp.txt

	while read line; 
	do
		python3 $pwd/tools/ipaddress.py $line >> $pwd/domain/$domain/$domain"_ip_address"
	done < $pwd/domain/$domain/$domain"_domain"
	echo "IP collection completed"


}



NC='\033[0m'
Green='\033[0;32m'
Red="\033[0;100m"
Blue="\033[0;34m"
pwd=`pwd`

source config.txt

export GOPATH=$HOME/go
	
printf "
			  ___        ___        _       _____      
			 / _ \__  __/ _ \ _ __ / |_ __ |___ / _ __ 
			| | | \ \/ / | | | '_ \| | '_ \  |_ \| '__|
			| |_| |>  <| |_| | |_) | | | | |___) | |   
			 \___//_/\_\____/| .__/|_|_| |_|____/|_|   
			                 |_|                       

					v1.6
				Made with <3 from INDIA
			
			    Developed By : Jimmi Simon\n
			 
			 ${Blue}configure API keys in config.txt${NC}		    
	"


banner="
	Usage: 0x0p1n3r.sh -d domain

	Options are:
		  -d  domain (required)
		  
	";



#checkrequirements	

proxy="http://$proxy";
burp="http://$burp";



while getopts ":d:" args;
do
	case $args in
		d)domain=$OPTARG;;
	esac
done



if [ "$domain" == "" ];
then
	echo "$banner";
	exit;
fi



printf "\n\n				${Blue}Selected domain ${Red} $domain ${NC}\n\n";

opt="
	1) subdomain enumeration
	2) Internal errors checking
	3) CRLF scanning
	4) Broken-link checking
	5) Parameters scanning
	6) Graphql endpoints scanning
	7) CVE scanning
	8) source-code checking - ( git,env,etc )
	9) search for javascript files
	10) ssrf scanning
	11) xss scanning
	12) SQL injection scanning
	13) SSTI scanning
	14) IP scanning
	15) nuclei scanning


";


while true
do
	echo "$opt";
	read -p "Enter your choice: " a
	case $a in
		1)
			echo "selected subdomain scanning";
			subdomainscan
		;;
		2)
			echo "selected internal error checking scanning";
			internalchecking
		;;
		3)
			echo "selected crlf scanning";
			crlfscan
		;;
		4)
			echo "selected brokenlink scanning";
			brokenlinkscan
		;;
		5)
			echo "selected parameter scanning";
			parametersscan
		;;
		6)
			echo "selected graphql scanning";
			graphqlscan
		;;
		7)
			echo "selected CVE scanning";
			cvescans
		;;
		8)
			echo "selected source-code scanning";
			sourcecodescan
		;;
		9)
			echo "selected javascript files scanning";
			javascriptfilesscan
		;;
		10)
			echo "selected ssrf scanning";
			ssrfscan
		;;
		11)
			echo "selected xss scanning";
			xssscan
		;;
		12)
			echo "selected SQL Injection scanning";
			sqlscan
		;;
		13)
			echo "selected SSTI scanning";
			sstiscan
		;;
		14)
			echo "selected IP scanning";
			ipscan
		;;
		15)
			echo "selected nuclei scanning";
			nucleiscan
		;;			
		*)
		echo "$opt"
		;;

	esac

done
