all: adv static/style.css

dep:
	go get -u github.com/mattn/go-sqlite3
	go get -u golang.org/x/crypto/bcrypt
	go get -u gopkg.in/russross/blackfriday.v2
	npm install tailwindcss
	npm install npx

adv: adv.go betterguid.go
	go build -o adv adv.go betterguid.go

static/style.css: twsrc.css
	npx tailwind build twsrc.css -o static/style.css

clean:
	rm -rf adv static/style.css

