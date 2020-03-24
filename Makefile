all: style.css

dep:
	npm install tailwindcss
	npm install npx

style.css: twsrc.css
	npx tailwind build twsrc.css -o style.css

clean:
	rm -rf style.css

