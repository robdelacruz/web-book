package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/russross/blackfriday.v2"
)

const ADMIN_ID = 1

type User struct {
	Userid   int64
	Username string
	Active   bool
	Email    string
}

type Site struct {
	Title string
	Desc  string
}

type Book struct {
	Bookid int64
	Name   string
	Desc   string
}

type Page struct {
	Pageid int64
	Bookid int64
	Title  string
	Body   string
}

func main() {
	os.Args = os.Args[1:]
	sw, parms := parseArgs(os.Args)

	// [-i new_file]  Create and initialize book file
	if sw["i"] != "" {
		dbfile := sw["i"]
		if fileExists(dbfile) {
			s := fmt.Sprintf("File '%s' already exists. Can't initialize it.\n", dbfile)
			fmt.Printf(s)
			os.Exit(1)
		}
		createAndInitTables(dbfile)
		os.Exit(0)
	}

	//$$ translate link test
	//body := "Now is the time for all good men to come to the aid of the party. You can decide to [[left room|turn left]] or [[right room|turn right]] or [[middle room]] or [[upper room|go up]]"
	//fmt.Printf("\n%s\n\n", translateLinks(body, "Space Patrol"))

	// Need to specify a db file as first parameter.
	if len(parms) == 0 {
		s := `Usage:

Start webservice using existing book file:
	adv <book_file>

Initialize new book file:
	nb -i <book_file>

`
		fmt.Printf(s)
		os.Exit(0)
	}

	// Exit if specified notes file doesn't exist.
	dbfile := parms[0]
	if !fileExists(dbfile) {
		s := fmt.Sprintf(`Book file '%s' doesn't exist. Create one using:
	nb -i <book_file>
`, dbfile)
		fmt.Printf(s)
		os.Exit(1)
	}

	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		fmt.Printf("Error opening '%s' (%s)\n", dbfile, err)
		os.Exit(1)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "./static/coffee.ico") })

	http.HandleFunc("/login/", loginHandler(db))
	http.HandleFunc("/logout/", logoutHandler(db))
	http.HandleFunc("/createaccount/", createaccountHandler(db))
	http.HandleFunc("/", indexHandler(db))
	http.HandleFunc("/createpage/", createpageHandler(db))
	http.HandleFunc("/editpage/", editpageHandler(db))
	http.HandleFunc("/createbook/", createbookHandler(db))
	http.HandleFunc("/editbook/", editbookHandler(db))
	port := "8000"
	fmt.Printf("Listening on %s...\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
	log.Fatal(err)
}

func parseArgs(args []string) (map[string]string, []string) {
	switches := map[string]string{}
	parms := []string{}

	standaloneSwitches := []string{}
	definitionSwitches := []string{"i"}
	fNoMoreSwitches := false
	curKey := ""

	for _, arg := range args {
		if fNoMoreSwitches {
			// any arg after "--" is a standalone parameter
			parms = append(parms, arg)
		} else if arg == "--" {
			// "--" means no more switches to come
			fNoMoreSwitches = true
		} else if strings.HasPrefix(arg, "--") {
			switches[arg[2:]] = "y"
			curKey = ""
		} else if strings.HasPrefix(arg, "-") {
			if listContains(definitionSwitches, arg[1:]) {
				// -a "val"
				curKey = arg[1:]
				continue
			}
			for _, ch := range arg[1:] {
				// -a, -b, -ab
				sch := string(ch)
				if listContains(standaloneSwitches, sch) {
					switches[sch] = "y"
				}
			}
		} else if curKey != "" {
			switches[curKey] = arg
			curKey = ""
		} else {
			// standalone parameter
			parms = append(parms, arg)
		}
	}

	return switches, parms
}

func listContains(ss []string, v string) bool {
	for _, s := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func fileExists(file string) bool {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func idtoi(sid string) int64 {
	if sid == "" {
		return -1
	}
	n, err := strconv.Atoi(sid)
	if err != nil {
		return -1
	}
	return int64(n)
}

func atoi(s string) int {
	if s == "" {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

func atof(s string) float64 {
	if s == "" {
		return -1.0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1.0
	}
	return f
}

func sqlstmt(db *sql.DB, s string) *sql.Stmt {
	stmt, err := db.Prepare(s)
	if err != nil {
		log.Fatalf("db.Prepare() sql: '%s'\nerror: '%s'", s, err)
	}
	return stmt
}

func sqlexec(db *sql.DB, s string, pp ...interface{}) (sql.Result, error) {
	stmt := sqlstmt(db, s)
	defer stmt.Close()
	return stmt.Exec(pp...)
}

func createAndInitTables(newfile string) {
	if fileExists(newfile) {
		s := fmt.Sprintf("File '%s' already exists. Can't initialize it.\n", newfile)
		fmt.Printf(s)
		os.Exit(1)
	}

	db, err := sql.Open("sqlite3", newfile)
	if err != nil {
		fmt.Printf("Error opening '%s' (%s)\n", newfile, err)
		os.Exit(1)
	}

	ss := []string{
		"BEGIN TRANSACTION;",
		"CREATE TABLE book (book_id INTEGER PRIMARY KEY NOT NULL, name TEXT, desc TEXT);",
		"CREATE TABLE page (page_id INTEGER PRIMARY KEY NOT NULL, book_id INTEGER NOT NULL, title TEXT, body TEXT);",
		"CREATE TABLE user (user_id INTEGER PRIMARY KEY NOT NULL, username TEXT, password TEXT, active INTEGER NOT NULL, email TEXT, CONSTRAINT unique_username UNIQUE (username));",
		"INSERT INTO user (user_id, username, password, active, email) VALUES (1, 'admin', '', 1, '');",
		"INSERT INTO book (book_id, name, desc) VALUES (1, 'Sesame Street Adventure', 'Join your favorite characters - Oscar the Grouch, Big Bird, Snuffleupagus, and Mr. Hooper on a gritty, urban adventure through the mean streets of Sesame Street.');",
		"INSERT INTO book (book_id, name, desc) VALUES (2, 'Escape', 'Based on the original *Escape* book by R.A. Montgomery from the Choose Your Own Adventure Books series. You''re the star of the story, choose from 27 possible endings.');",
		"INSERT INTO book (book_id, name, desc) VALUES (3, 'Space Patrol', 'You are the commander of Space Rescue Emergency Vessel III. You have spent almost six months alone in space, and your only companion is your computer, Henry. You are steering your ship through a meteorite shower when an urgent signal comes from headquarters- a ship in your sector is under attack by space pirates!');",
		"INSERT INTO book (book_id, name, desc) VALUES (4, 'Prisoner of the Ant People', 'R. A. Montgomery takes YOU on an otherworldly adventure as you fight off the the feared Ant People, who have recently joined forces with the Evil Power Master.');",
		"INSERT INTO book (book_id, name, desc) VALUES (5, 'War with the Evil Power Master', 'You are the commander of the Lacoonian System Rapid Force response team, in charge of protecting all planets in the System. You learn that the Evil Power Master has zeroed in on three planets and plans to destroy them. The safety of the Lacoonian System depends on you!');",
		"COMMIT;",
	}

	for _, s := range ss {
		_, err := sqlexec(db, s)
		if err != nil {
			log.Printf("DB error setting up newsboard db on '%s' (%s)\n", newfile, err)
			os.Exit(1)
		}
	}
}

func getLoginUser(r *http.Request, db *sql.DB) *User {
	var u User
	u.Userid = -1

	c, err := r.Cookie("userid")
	if err != nil {
		return &u
	}
	userid := idtoi(c.Value)
	if userid == -1 {
		return &u
	}
	return queryUser(db, userid)
}

func queryUser(db *sql.DB, userid int64) *User {
	var u User
	u.Userid = -1

	s := "SELECT user_id, username, active, email FROM user WHERE user_id = ?"
	row := db.QueryRow(s, userid)
	err := row.Scan(&u.Userid, &u.Username, &u.Active, &u.Email)
	if err == sql.ErrNoRows {
		return &u
	}
	if err != nil {
		fmt.Printf("queryUser() db error (%s)\n", err)
		return &u
	}
	return &u
}

func queryUsername(db *sql.DB, username string) *User {
	var u User
	u.Userid = -1

	s := "SELECT user_id, username, active, email FROM user WHERE username = ?"
	row := db.QueryRow(s, username)
	err := row.Scan(&u.Userid, &u.Username, &u.Active, &u.Email)
	if err == sql.ErrNoRows {
		return &u
	}
	if err != nil {
		fmt.Printf("queryUser() db error (%s)\n", err)
		return &u
	}
	return &u
}

func querySite(db *sql.DB) *Site {
	var site Site
	s := "SELECT title, desc FROM site WHERE site_id = 1"
	row := db.QueryRow(s)
	err := row.Scan(&site.Title, &site.Desc)
	if err == sql.ErrNoRows {
		// Site settings row not defined yet, just use default Site values.
		site.Title = "Game Book"
		site.Desc = ""
	} else if err != nil {
		// DB error, log then use common site settings.
		log.Printf("error reading site settings for siteid %d (%s)\n", 1, err)
		site.Title = "Game Book"
	}
	return &site
}

func isCorrectPassword(inputPassword, hashedpwd string) bool {
	if hashedpwd == "" && inputPassword == "" {
		return true
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedpwd), []byte(inputPassword))
	if err != nil {
		return false
	}
	return true
}

func hashPassword(pwd string) string {
	hashedpwd, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hashedpwd)
}

func loginUser(w http.ResponseWriter, userid int64) {
	suserid := fmt.Sprintf("%d", userid)
	c := http.Cookie{
		Name:  "userid",
		Value: suserid,
		Path:  "/",
		// Expires: time.Now().Add(24 * time.Hour),
	}
	http.SetCookie(w, &c)
}

func unescapeUrl(qurl string) string {
	returl := "/"
	if qurl != "" {
		returl, _ = url.QueryUnescape(qurl)
	}
	return returl
}

func handleDbErr(w http.ResponseWriter, err error, sfunc string) bool {
	if err == sql.ErrNoRows {
		http.Error(w, "Not found.", 404)
		return true
	}
	if err != nil {
		log.Printf("%s: database error (%s)\n", sfunc, err)
		http.Error(w, "Server database error.", 500)
		return true
	}
	return false
}

func validateLogin(w http.ResponseWriter, login *User) bool {
	if login.Userid == -1 {
		http.Error(w, "Not logged in.", 401)
		return false
	}
	if !login.Active {
		http.Error(w, "Not an active user.", 401)
		return false
	}
	return true
}

func queryBook(db *sql.DB, bookid int64) *Book {
	var b Book
	b.Bookid = -1

	s := "SELECT book_id, name, desc FROM book WHERE book_id = ?"
	row := db.QueryRow(s, bookid)
	err := row.Scan(&b.Bookid, &b.Name, &b.Desc)
	if err == sql.ErrNoRows {
		return nil
		return &b
	}
	if err != nil {
		fmt.Printf("queryBook() db error (%s)\n", err)
		return nil
	}
	return &b
}

func queryBookName(db *sql.DB, name string) *Book {
	var b Book
	s := "SELECT book_id, name, desc FROM book WHERE name = ?"
	row := db.QueryRow(s, name)
	err := row.Scan(&b.Bookid, &b.Name, &b.Desc)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		fmt.Printf("queryBook() db error (%s)\n", err)
		return nil
	}
	return &b
}

func queryPage(db *sql.DB, pageid, bookid int64) *Page {
	var p Page
	p.Pageid = -1

	s := "SELECT page_id, title, body FROM page WHERE page_id = ? AND book_id = ?"
	row := db.QueryRow(s, pageid, bookid)
	err := row.Scan(&p.Pageid, &p.Title, &p.Body)
	if err == sql.ErrNoRows {
		return &p
	}
	if err != nil {
		fmt.Printf("queryPage() db error (%s)\n", err)
		return &p
	}
	return &p
}

func queryPageName(db *sql.DB, bookid int64, title string) *Page {
	var p Page
	s := "SELECT page_id, book_id, title, body FROM page WHERE book_id = ? AND title = ?"
	row := db.QueryRow(s, bookid, title)
	err := row.Scan(&p.Pageid, &p.Bookid, &p.Title, &p.Body)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		fmt.Printf("queryBook() db error (%s)\n", err)
		return nil
	}
	return &p
}

// Helper function to make fmt.Fprintf(w, ...) calls shorter.
// Ex.
// Replace:
//   fmt.Fprintf(w, "<p>Some text %s.</p>", str)
//   fmt.Fprintf(w, "<p>Some other text %s.</p>", str)
// with the shorter version:
//   P := makeFprintf(w)
//   P("<p>Some text %s.</p>", str)
//   P("<p>Some other text %s.</p>", str)
func makeFprintf(w io.Writer) func(format string, a ...interface{}) (n int, err error) {
	return func(format string, a ...interface{}) (n int, err error) {
		return fmt.Fprintf(w, format, a...)
	}
}

func printHead(w io.Writer, jsurls []string, cssurls []string) {
	P := makeFprintf(w)
	P("<!DOCTYPE html>\n")
	P("<html>\n")
	P("<head>\n")
	P("<meta charset=\"utf-8\">\n")
	P("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	P("<title>Website</title>\n")
	P("<link rel=\"stylesheet\" type=\"text/css\" href=\"/static/style.css\">\n")
	for _, cssurl := range cssurls {
		P("<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\">\n", cssurl)
	}
	for _, jsurl := range jsurls {
		P("<script src=\"%s\" defer></script>\n", jsurl)
	}
	P("</head>\n")
	P("<body>\n")
	P("<section class=\"body\">\n")
}

func printFoot(w io.Writer) {
	P := makeFprintf(w)
	P("</section>\n")
	P("</body>\n")
	P("</html>\n")
}

func printNav(w http.ResponseWriter, r *http.Request, db *sql.DB, login *User, b *Book) {
	if login == nil {
		login = getLoginUser(r, db)
	}
	if b == nil {
		bookName, _ := parseBookPageUrl(r.URL.Path)
		if bookName != "" {
			b = queryBookName(db, bookName)
		}
	}

	P := makeFprintf(w)
	P("<header class=\"p-2 bg-gray-800 text-gray-200\">\n")
	P("<nav class=\"flex flex-row justify-between\">\n")

	// Menu section (left part)
	P("<div>\n")
	P("<h1 class=\"inline font-bold mr-2\"><a href=\"/\">Game Books</a></h1>\n")
	P("<ul class=\"list-none inline\">\n")
	if b != nil {
		P("  <li class=\"inline\"><a class=\"link-1 no-underline\" href=\"%s\">%s</a></li>\n", pageUrl(b.Name, ""), b.Name)
	}
	P("</ul>\n")
	P("</div>\n")

	// User section (right part)
	P("<div>\n")
	P("<ul class=\"list-none inline text-xs\">\n")
	if login.Userid == -1 {
		P("<li class=\"inline\"><a href=\"/login\">login</a></li>\n")
	} else if login.Userid == ADMIN_ID {
		P("<li class=\"inline\"><a href=\"/adminsetup/\">%s</a></li>\n", login.Username)
		P("<li class=\"inline\"><a href=\"/logout\">logout</a></li>\n")
	} else {
		P("<li class=\"inline\"><a href=\"/usersetup/\">%s</a></li>\n", login.Username)
		P("<li class=\"inline\"><a href=\"/logout\">logout</a></li>\n")
	}
	P("</ul>\n")
	P("</div>\n")

	P("</nav>\n")
	P("</header>\n")
}

func loginHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var errmsg string
		var f struct{ username, password string }

		login := getLoginUser(r, db)
		qfrom := r.FormValue("from")

		if r.Method == "POST" {
			f.username = r.FormValue("username")
			f.password = r.FormValue("password")

			s := "SELECT user_id, password, active FROM user WHERE username = ?"
			row := db.QueryRow(s, f.username, f.password)

			var userid int64
			var hashedpwd string
			var active int
			err := row.Scan(&userid, &hashedpwd, &active)

			for {
				if err == sql.ErrNoRows {
					errmsg = "Incorrect username or password"
					break
				}
				if err != nil {
					errmsg = "A problem occured. Please try again."
					break
				}
				if !isCorrectPassword(f.password, hashedpwd) {
					errmsg = "Incorrect username or password"
					break
				}
				if active == 0 {
					errmsg = fmt.Sprintf("User '%s' is inactive.", f.username)
					break
				}

				loginUser(w, userid)

				http.Redirect(w, r, unescapeUrl(qfrom), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, nil)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row content-start\">\n")
		P("    <section class=\"widget-1\">\n")
		P("      <h1 class=\"fg-2 mb-4\">Login</h1>")
		P("      <form class=\"mb-4\" action=\"/login/?from=%s\" method=\"post\">\n", qfrom)
		if errmsg != "" {
			P("    <div class=\"mb-2\">\n")
			P("      <p class=\"text-red-500\">%s</p>\n", errmsg)
			P("    </div>\n")
		}
		P("        <div class=\"mb-2\">\n")
		P("          <label class=\"block label-1\" for=\"username\">username</label>\n")
		P("          <input class=\"block input-1 w-full\" id=\"username\" name=\"username\" type=\"text\" size=\"20\" value=\"%s\">\n", f.username)
		P("        </div>\n")

		P("        <div class=\"mb-4\">\n")
		P("          <label class=\"block label-1\" for=\"password\">password</label>\n")
		P("          <input class=\"block input-1 w-full\" id=\"password\" name=\"password\" type=\"password\" size=\"20\" value=\"%s\">\n", f.password)
		P("        </div>\n")

		P("        <div class=\"\">\n")
		P("          <button class=\"block btn-1 text-gray-800 bg-gray-200\" type=\"submit\">login</button>\n")
		P("        </div>\n")
		P("      </form>\n")

		P("      <p class=\"text-center\"><a class=\"link-2\" href=\"/createaccount/?from=%s\">Create New Account</a></p>\n", qfrom)
		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")

		printFoot(w)
	}
}

func logoutHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		c := http.Cookie{
			Name:   "userid",
			Value:  "",
			Path:   "/",
			MaxAge: 0,
		}
		http.SetCookie(w, &c)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func isUsernameExists(db *sql.DB, username string) bool {
	s := "SELECT user_id FROM user WHERE username = ?"
	row := db.QueryRow(s, username)
	var userid int64
	err := row.Scan(&userid)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		return false
	}
	return true
}

func createaccountHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var errmsg string
		var f struct{ username, email, password, password2 string }

		login := getLoginUser(r, db)
		qfrom := r.FormValue("from")

		if r.Method == "POST" {
			f.username = r.FormValue("username")
			f.email = r.FormValue("email")
			f.password = r.FormValue("password")
			f.password2 = r.FormValue("password2")
			for {
				if f.password != f.password2 {
					errmsg = "re-entered password doesn't match"
					f.password = ""
					f.password2 = ""
					break
				}
				if isUsernameExists(db, f.username) {
					errmsg = fmt.Sprintf("username '%s' already exists", f.username)
					break
				}

				hashedPassword := hashPassword(f.password)
				s := "INSERT INTO user (username, password, active, email) VALUES (?, ?, ?, ?);"
				result, err := sqlexec(db, s, f.username, hashedPassword, 1, f.email)
				if err != nil {
					log.Printf("DB error creating user: %s\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				newid, err := result.LastInsertId()
				if err == nil {
					loginUser(w, newid)
				} else {
					// DB doesn't support getting newly added userid, so login manually.
					qfrom = "/login/"
				}

				http.Redirect(w, r, unescapeUrl(qfrom), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, nil)

		P := makeFprintf(w)
		P("<section class=\"main\">\n")
		P("<form class=\"simpleform\" action=\"/createaccount/?from=%s\" method=\"post\">\n", qfrom)
		P("<h1 class=\"heading\">Create Account</h1>")
		if errmsg != "" {
			P("<div class=\"control\">\n")
			P("<p class=\"error\">%s</p>\n", errmsg)
			P("</div>\n")
		}
		P("<div class=\"control\">\n")
		P("<label for=\"username\">username</label>\n")
		P("<input id=\"username\" name=\"username\" type=\"text\" size=\"20\" value=\"%s\">\n", f.username)
		P("</div>\n")

		P("<div class=\"control\">\n")
		P("<label for=\"email\">email</label>\n")
		P("<input id=\"email\" name=\"email\" type=\"email\" size=\"20\" value=\"%s\">\n", f.email)
		P("</div>\n")

		P("<div class=\"control\">\n")
		P("<label for=\"password\">password</label>\n")
		P("<input id=\"password\" name=\"password\" type=\"password\" size=\"20\" value=\"%s\">\n", f.password)
		P("</div>\n")

		P("<div class=\"control\">\n")
		P("<label for=\"password2\">re-enter password</label>\n")
		P("<input id=\"password2\" name=\"password2\" type=\"password\" size=\"20\" value=\"%s\">\n", f.password2)
		P("</div>\n")

		P("<div class=\"control\">\n")
		P("<button class=\"submit\">create account</button>\n")
		P("</div>\n")
		P("</form>\n")
		P("</section>\n")

		printFoot(w)
	}
}

func parseBookPageUrl(url string) (string, string) {
	var bookName, pageName string

	sre := `^/(.+?)(?:/(.*?))?/?$`
	re := regexp.MustCompile(sre)
	matches := re.FindStringSubmatch(url)
	if matches == nil {
		return bookName, pageName
	}
	bookName = matches[1]
	if len(matches) > 2 {
		pageName = matches[2]
	}
	return underscoreToSpace(bookName), underscoreToSpace(pageName)
}

func spaceToUnderscore(s string) string {
	return strings.Replace(s, " ", "_", -1)
}

func underscoreToSpace(s string) string {
	return strings.Replace(s, "_", " ", -1)
}

func indexHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		login := getLoginUser(r, db)

		bookName, pageTitle := parseBookPageUrl(r.URL.Path)
		var b *Book
		if bookName != "" {
			b = queryBookName(db, bookName)
			if b == nil {
				http.Error(w, fmt.Sprintf("'%s' not found.", bookName), 404)
				return
			}
		}

		if bookName == "" {
			printBooksMenu(w, r, db, login)
			return
		}
		printPage(w, r, db, login, b, pageTitle)
	}
}

func printBooksMenu(w http.ResponseWriter, r *http.Request, db *sql.DB, login *User) {
	w.Header().Set("Content-Type", "text/html")
	printHead(w, nil, nil)
	printNav(w, r, db, login, nil)

	P := makeFprintf(w)
	P("<section class=\"container main-container\">\n")
	P("  <section class=\"flex flex-row content-start\">\n")
	P("    <section class=\"widget-1 min-h-64 flex flex-col\">\n")
	P("      <article class=\"w-page flex-grow\">\n")
	P("        <h1 class=\"fg-2 mb-4\">Select Book:</h1>\n")

	s := "SELECT book_id, name, desc FROM book ORDER BY book_id"
	rows, err := db.Query(s)
	if handleDbErr(w, err, "indexhandler") {
		return
	}
	var b Book
	for rows.Next() {
		rows.Scan(&b.Bookid, &b.Name, &b.Desc)
		P("<div class=\"ml-2 mb-2\">\n")
		P("  <div class=\"flex flex-row justify-between\">\n")
		P("    <a class=\"block link-1 no-underline text-base\" href=\"/%s\">%s</a>\n", spaceToUnderscore(b.Name), b.Name)
		if login.Userid == ADMIN_ID {
			P("    <a class=\"block link-2 text-xs\" href=\"/editbook?bookid=%d\">Edit</a>\n", b.Bookid)
		}
		P("  </div>\n")
		if b.Desc != "" {
			P("  <div class=\"text-xs fg-2\">\n")
			P(parseMarkdown(b.Desc))
			P("  </div>\n")
		}
		P("</div>\n")
	}
	P("      </article>\n")

	if login.Userid == ADMIN_ID {
		P("<div class=\"flex flex-row justify-around bg-3 fg-3 p-1\">\n")
		P("  <ul class=\"list-none text-xs\">\n")
		P("    <li class=\"inline\"><a class=\"underline mr-2\" href=\"/createbook/\">Create Book</a></li>\n")
		P("  </ul>\n")
		P("</div>\n")
	}

	P("    </section>\n")
	P("  </section>\n")
	P("</section>\n")

	printFoot(w)
}

func printPage(w http.ResponseWriter, r *http.Request, db *sql.DB, login *User, b *Book, pageTitle string) {
	if pageTitle == "" {
		pageTitle = "start"
	}

	w.Header().Set("Content-Type", "text/html")
	printHead(w, nil, nil)
	printNav(w, r, db, login, nil)

	P := makeFprintf(w)
	P("<section class=\"container main-container\">\n")
	P("  <section class=\"flex flex-row content-start\">\n")
	P("    <section class=\"widget-1 min-h-64 flex flex-col\">\n")
	P("      <article class=\"page w-page flex-grow\">\n")
	p := queryPageName(db, b.Bookid, pageTitle)
	if p == nil {
		P("<h1 class=\"fg-2 mb-4\">Page Not Found</h1>\n")
	} else {
		p.Body = translateLinks(p.Body, b.Name)
		P(parseMarkdown(p.Body))
	}
	P("      </article>\n")

	if login.Userid == ADMIN_ID {
		P("<div class=\"flex flex-row justify-around bg-3 fg-3 p-1\">\n")
		P("  <ul class=\"list-none text-xs\">\n")
		if p == nil {
			P("    <li class=\"inline\"><a class=\"underline mr-2\" href=\"/createpage?bookid=%d&title=%s\">Create Page</a></li>\n", b.Bookid, url.QueryEscape(pageTitle))
		} else {
			P("    <li class=\"inline\"><a class=\"underline mr-2\" href=\"/editpage?bookid=%d&pageid=%d\">Edit</a></li>\n", b.Bookid, p.Pageid)
			P("    <li class=\"inline\"><a class=\"underline\" href=\"/delpage?bookid=%d&pageid=%d\">Delete</a></li>\n", b.Bookid, p.Pageid)
		}
		P("  </ul>\n")
		P("</div>\n")
	}

	P("    </section>\n")
	P("  </section>\n")
	P("</section>\n")
	printFoot(w)
}

func pageUrl(bookName, pageTitle string) string {
	return fmt.Sprintf("/%s/%s", spaceToUnderscore(bookName), spaceToUnderscore(pageTitle))
}

// Translate wikitext links into markdown links.
// "[[Texas|Lone Star State]]" => "[Lone Star State](/Texas)"
// "[[Enterprise Bridge|Go to Captain's Bridge]]" => "[Go to Captain's Bridge](/Enterprise_Bridge)"
func translateLinks(body, bookName string) string {
	body = translateSimpleLinks(body, bookName)
	body = translatePipeLinks(body, bookName)
	return body
}

func translateSimpleLinks(body, bookName string) string {
	sre := `\[\[([\w\s/]+?)\]\]`
	re := regexp.MustCompile(sre)

	// Change wikitext links to use page link with underscores:
	// "[[Enterprise Bridge]]" => "{{/Book_Name/Enterprise_Bridge|Enterprise Bridge}}"
	body = re.ReplaceAllStringFunc(body, func(slink string) string {
		matches := re.FindStringSubmatch(slink)
		return fmt.Sprintf("{{/%s/%s|%s}}", spaceToUnderscore(bookName), spaceToUnderscore(matches[1]), matches[1])
	})

	// Replace wikitext link with equivalent markdown link:
	// "{{/Book_Name/Enterprise_Bridge|Enterprise Bridge}}" => "[Enterprise Bridge](/Book_Name/Enterprise_Bridge)"
	sre = `\{\{([\w\s/]+?)\|(.+?)\}\}`
	re = regexp.MustCompile(sre)
	body = re.ReplaceAllString(body, "[$2]($1)")
	return body
}

func translatePipeLinks(body, bookName string) string {
	sre := `\[\[([\w\s/]+?)\|(.+?)\]\]`
	re := regexp.MustCompile(sre)

	// Change wikitext links to use page link with underscores:
	// "[[Enterprise Bridge|Go to bridge]]" => "[[/Book_Name/Enterprise_Bridge|Go to bridge]]"
	body = re.ReplaceAllStringFunc(body, func(slink string) string {
		matches := re.FindStringSubmatch(slink)
		return fmt.Sprintf("[[/%s/%s|%s]]", spaceToUnderscore(bookName), spaceToUnderscore(matches[1]), matches[2])
	})

	// Replace wikitext link with equivalent markdown link:
	// "[[/Book_Name/Enterprise_Bridge|Go to bridge]]" => "[Go to bridge](/Book_Name/Enterprise_Bridge)"
	body = re.ReplaceAllString(body, "[$2]($1)")
	return body
}

func parseMarkdown(s string) string {
	return string(blackfriday.Run([]byte(s), blackfriday.WithExtensions(blackfriday.HardLineBreak)))
}

func createpageHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var p Page

		login := getLoginUser(r, db)
		bookid := idtoi(r.FormValue("bookid"))
		p.Title = strings.TrimSpace(r.FormValue("title"))

		if login.Userid != ADMIN_ID {
			http.Error(w, "admin user required", 401)
			return
		}
		if bookid == -1 {
			http.Error(w, "bookid required", 401)
			return
		}
		if p.Title == "" {
			http.Error(w, "title required", 401)
			return
		}
		b := queryBook(db, bookid)
		if b == nil {
			http.Error(w, fmt.Sprintf("bookid %d not found", bookid), 401)
			return
		}

		var errmsg string
		if r.Method == "POST" {
			p.Body = strings.TrimSpace(r.FormValue("body"))
			for {
				if p.Body == "" {
					errmsg = "Please enter some text."
					break
				}

				var err error
				s := "INSERT INTO page (book_id, title, body) VALUES (?, ?, ?)"
				_, err = sqlexec(db, s, bookid, p.Title, p.Body)
				if err != nil {
					log.Printf("DB error saving page (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, pageUrl(b.Name, p.Title), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, b)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row content-start\">\n")
		P("    <section class=\"widget-1\">\n")
		P("      <form class=\"w-page mb-4\" method=\"post\" action=\"/createpage/?bookid=%d&title=%s\">\n", bookid, url.QueryEscape(p.Title))
		P("      <h1 class=\"fg-2 mb-4\">Create Page '%s'</h1>", p.Title)
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

		P("  <div class=\"mb-2\">\n")
		P("    <label class=\"block label-1\" for=\"title\">title</label>\n")
		P("    <input class=\"block input-1 w-full\" id=\"title\" name=\"title\" type=\"text\" size=\"60\" value=\"%s\" readonly>\n", p.Title)
		P("  </div>\n")

		P("  <div class=\"mb-4\">\n")
		P("    <label class=\"block label-1\" for=\"body\">text</label>\n")
		P("    <textarea class=\"block input-1 w-full\" id=\"body\" name=\"body\" rows=\"15\">%s</textarea>\n", p.Body)
		P("  </div>\n")

		P("  <div class=\"\">\n")
		P("    <button class=\"block btn-1 text-gray-800 bg-gray-200\" type=\"submit\">submit</button>\n")
		P("  </div>\n")
		P("</form>\n")

		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")
		printFoot(w)
	}
}

func editpageHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		login := getLoginUser(r, db)
		bookid := idtoi(r.FormValue("bookid"))
		pageid := idtoi(r.FormValue("pageid"))

		if login.Userid != ADMIN_ID {
			http.Error(w, "admin user required", 401)
			return
		}
		if bookid == -1 {
			http.Error(w, "bookid required", 401)
			return
		}
		if pageid == -1 {
			http.Error(w, "pageid required", 401)
			return
		}

		b := queryBook(db, bookid)
		if b == nil {
			http.Error(w, fmt.Sprintf("bookid %d not found", bookid), 401)
			return
		}
		p := queryPage(db, pageid, bookid)
		if p == nil {
			http.Error(w, fmt.Sprintf("pageid %d not found", pageid), 401)
			return
		}

		var errmsg string
		if r.Method == "POST" {
			p.Title = strings.TrimSpace(r.FormValue("title"))
			p.Body = strings.TrimSpace(r.FormValue("body"))
			for {
				if p.Title == "" {
					errmsg = "Please enter a title."
					break
				}
				if p.Body == "" {
					errmsg = "Please enter some text."
					break
				}

				var err error
				s := "UPDATE page SET title = ?, body = ? WHERE page_id = ?"
				_, err = sqlexec(db, s, p.Title, p.Body, p.Pageid)
				if err != nil {
					log.Printf("DB error saving page (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, pageUrl(b.Name, p.Title), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, b)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row content-start\">\n")
		P("    <section class=\"widget-1\">\n")
		P("      <form class=\"w-page mb-4\" method=\"post\" action=\"/editpage/?bookid=%d&pageid=%d\">\n", bookid, pageid)
		P("      <h1 class=\"fg-2 mb-4\">Edit Page '%s'</h1>", p.Title)
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

		P("  <div class=\"mb-2\">\n")
		P("    <label class=\"block label-1\" for=\"title\">title</label>\n")
		P("    <input class=\"block input-1 w-full\" id=\"title\" name=\"title\" type=\"text\" size=\"60\" value=\"%s\" readonly>\n", p.Title)
		P("  </div>\n")

		P("  <div class=\"mb-4\">\n")
		P("    <label class=\"block label-1\" for=\"body\">text</label>\n")
		P("    <textarea class=\"block input-1 w-full\" id=\"body\" name=\"body\" rows=\"15\">%s</textarea>\n", p.Body)
		P("  </div>\n")

		P("  <div class=\"\">\n")
		P("    <button class=\"block btn-1 text-gray-800 bg-gray-200\" type=\"submit\">submit</button>\n")
		P("  </div>\n")
		P("</form>\n")

		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")
		printFoot(w)
	}
}

func createbookHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var b Book

		login := getLoginUser(r, db)
		if login.Userid != ADMIN_ID {
			http.Error(w, "admin user required", 401)
			return
		}

		var errmsg string
		if r.Method == "POST" {
			b.Name = strings.TrimSpace(r.FormValue("name"))
			b.Desc = strings.TrimSpace(r.FormValue("desc"))
			for {
				if b.Name == "" {
					errmsg = "Please enter a book name."
					break
				}

				var err error
				s := "INSERT INTO book (name, desc) VALUES (?, ?)"
				_, err = sqlexec(db, s, b.Name, b.Desc)
				if err != nil {
					log.Printf("DB error saving book (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, pageUrl(b.Name, ""), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, nil)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row content-start\">\n")
		P("    <section class=\"widget-1\">\n")
		P("      <form class=\"w-page mb-4\" method=\"post\" action=\"/createbook/\">\n")
		P("      <h1 class=\"fg-2 mb-4\">Create Book</h1>")
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

		P("  <div class=\"mb-2\">\n")
		P("    <label class=\"block label-1\" for=\"name\">name</label>\n")
		P("    <input class=\"block input-1 w-full\" id=\"name\" name=\"name\" type=\"text\" size=\"60\" value=\"%s\">\n", b.Name)
		P("  </div>\n")

		P("  <div class=\"mb-4\">\n")
		P("    <label class=\"block label-1\" for=\"desc\">description</label>\n")
		P("    <textarea class=\"block input-1 w-full\" id=\"desc\" name=\"desc\" rows=\"10\">%s</textarea>\n", b.Desc)
		P("  </div>\n")

		P("  <div class=\"\">\n")
		P("    <button class=\"block btn-1 text-gray-800 bg-gray-200\" type=\"submit\">submit</button>\n")
		P("  </div>\n")
		P("</form>\n")

		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")
		printFoot(w)
	}
}

func editbookHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		login := getLoginUser(r, db)
		if login.Userid != ADMIN_ID {
			http.Error(w, "admin user required", 401)
			return
		}

		bookid := idtoi(r.FormValue("bookid"))
		if bookid == -1 {
			http.Error(w, "bookid required", 401)
			return
		}
		b := queryBook(db, bookid)
		if b == nil {
			http.Error(w, fmt.Sprintf("bookid %d not found", bookid), 401)
			return
		}

		var errmsg string
		if r.Method == "POST" {
			b.Name = strings.TrimSpace(r.FormValue("name"))
			b.Desc = strings.TrimSpace(r.FormValue("desc"))
			for {
				if b.Name == "" {
					errmsg = "Please enter a book name."
					break
				}

				var err error
				s := "UPDATE book SET name = ?, desc = ? WHERE book_id = ?"
				_, err = sqlexec(db, s, b.Name, b.Desc, b.Bookid)
				if err != nil {
					log.Printf("DB error saving book (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, nil)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row content-start\">\n")
		P("    <section class=\"widget-1\">\n")
		P("      <form class=\"w-page mb-4\" method=\"post\" action=\"/editbook/?bookid=%d\">\n", bookid)
		P("      <h1 class=\"fg-2 mb-4\">Edit Book</h1>")
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

		P("  <div class=\"mb-2\">\n")
		P("    <label class=\"block label-1\" for=\"name\">name</label>\n")
		P("    <input class=\"block input-1 w-full\" id=\"name\" name=\"name\" type=\"text\" size=\"60\" value=\"%s\">\n", b.Name)
		P("  </div>\n")

		P("  <div class=\"mb-4\">\n")
		P("    <label class=\"block label-1\" for=\"desc\">description</label>\n")
		P("    <textarea class=\"block input-1 w-full\" id=\"desc\" name=\"desc\" rows=\"10\">%s</textarea>\n", b.Desc)
		P("  </div>\n")

		P("  <div class=\"\">\n")
		P("    <button class=\"block btn-1 text-gray-800 bg-gray-200\" type=\"submit\">submit</button>\n")
		P("  </div>\n")
		P("</form>\n")

		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")
		printFoot(w)
	}
}
