all: adv static/style.css

apt-install:
	sudo apt install curl software-properties-common
	curl -sL https://deb.nodesource.com/setup_13.x | sudo bash -
	sudo apt install nodejs

go-get:
	go get -u github.com/mattn/go-sqlite3
	go get -u golang.org/x/crypto/bcrypt
	go get -u gopkg.in/russross/blackfriday.v2

npm-install:
	sudo npm install -g tailwindcss
	sudo npm install -g npx
	sudo npm install -g cssnano --save-dev
	sudo npm install -g postcss-cli

adv: adv.go
	go build -o adv adv.go

static/style.css: twsrc.css
	npx tailwind build twsrc.css -o twsrc.o 1>/dev/null
	npx postcss twsrc.o > static/style.css

clean:
	rm -rf adv *.o static/style.css

