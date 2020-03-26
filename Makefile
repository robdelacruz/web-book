all: adv static/style.css

dep:
	npm install tailwindcss
	npm install npx

adv: adv.go
	go build -o adv adv.go

static/style.css: twsrc.css
	npx tailwind build twsrc.css -o static/style.css

clean:
	rm -rf adv static/style.css

