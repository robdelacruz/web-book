all: adv static/style.css

ppa:
	apt-get install curl python-software-properties
	curl -sL https://deb.nodesource.com/setup_13.x | sudo bash -
	sudo apt install nodejs

dep:
	#go get -u github.com/mattn/go-sqlite3
	#go get -u golang.org/x/crypto/bcrypt
	#go get -u gopkg.in/russross/blackfriday.v2
	npm install tailwindcss
	npm install npx
	npm install cssnano --save-dev
	npm install postcss-cli

adv: adv.go
	go build -o adv adv.go

static/style.css: twsrc.css
	npx tailwind build twsrc.css -o twsrc.o 1>/dev/null
	npx postcss twsrc.o > static/style.css

clean:
	rm -rf adv *.o static/style.css

