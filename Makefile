all: style.css

style.css: twsrc.css
	npx tailwind build twsrc.css -o style.css

clean:
	rm -rf style.css

