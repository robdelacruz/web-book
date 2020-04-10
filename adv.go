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
	Bookid      int64
	Name        string
	Desc        string
	Startpageid int64
}

type Page struct {
	Pageid int64
	Bookid int64
	Body   string
}

type Bookmark struct {
	Userid      int64
	Bookid      int64
	Pageid      int64
	Prevpageids string
	Desc        string
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
	http.HandleFunc("/createbookmark/", createbookmarkHandler(db))
	http.HandleFunc("/bookmarks/", bookmarksHandler(db))
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

func txstmt(tx *sql.Tx, s string) *sql.Stmt {
	stmt, err := tx.Prepare(s)
	if err != nil {
		log.Fatalf("tx.Prepare() sql: '%s'\nerror: '%s'", s, err)
	}
	return stmt
}

func txexec(tx *sql.Tx, s string, pp ...interface{}) (sql.Result, error) {
	stmt := txstmt(tx, s)
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
		"CREATE TABLE book (book_id INTEGER PRIMARY KEY NOT NULL, name TEXT, desc TEXT, startpage_id INTEGER DEFAULT 0);",
		"CREATE TABLE page (page_id INTEGER PRIMARY KEY NOT NULL, book_id INTEGER NOT NULL, body TEXT);",
		"CREATE TABLE user (user_id INTEGER PRIMARY KEY NOT NULL, username TEXT, password TEXT, active INTEGER NOT NULL, email TEXT, CONSTRAINT unique_username UNIQUE (username));",
		"INSERT INTO user (user_id, username, password, active, email) VALUES (1, 'admin', '', 1, '');",
		"CREATE TABLE bookmark (user_id INTEGER NOT NULL, book_id INTEGER NOT NULL, page_id INTEGER NOT NULL, prevpageids TEXT, desc TEXT);",
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
	}
	for _, s := range ss {
		_, err := txexec(tx, s)
		if err != nil {
			tx.Rollback()
			log.Printf("DB error (%s)\n", err)
			os.Exit(1)
		}
	}
	err = tx.Commit()
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
	}

	_, err = createBook(db, &Book{
		Name: "Sesame Street Adventure",
		Desc: `Join your favorite characters - Oscar the Grouch, Big Bird, Snuffleupagus, and Mr. Hooper on a gritty, urban adventure through the mean streets of Sesame Street.`,
	}, "")
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
	}
	_, err = createBook(db, &Book{
		Name: "Escape",
		Desc: `Based on the original *Escape* book by R.A. Montgomery from the Choose Your Own Adventure Books series. You''re the star of the story, choose from 27 possible endings.`,
	}, "")
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
	}
	_, err = createBook(db, &Book{
		Name: "Space Patrol",
		Desc: `You are the commander of Space Rescue Emergency Vessel III. You have spent almost six months alone in space, and your only companion is your computer, Henry. You are steering your ship through a meteorite shower when an urgent signal comes from headquarters- a ship in your sector is under attack by space pirates!`,
	}, "")
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
	}
	_, err = createBook(db, &Book{
		Name: "Prisoner of the Ant People",
		Desc: `R. A. Montgomery takes YOU on an otherworldly adventure as you fight off the the feared Ant People, who have recently joined forces with the Evil Power Master.`,
	}, "")
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
	}
	_, err = createBook(db, &Book{
		Name: "War with the Evil Power Master",
		Desc: `You are the commander of the Lacoonian System Rapid Force response team, in charge of protecting all planets in the System. You learn that the Evil Power Master has zeroed in on three planets and plans to destroy them. The safety of the Lacoonian System depends on you!`,
	}, "")
	if err != nil {
		log.Printf("DB error (%s)\n", err)
		os.Exit(1)
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

func handleTxErr(tx *sql.Tx, err error) bool {
	if err != nil {
		tx.Rollback()
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

	s := "SELECT book_id, name, desc, startpage_id FROM book WHERE book_id = ?"
	row := db.QueryRow(s, bookid)
	err := row.Scan(&b.Bookid, &b.Name, &b.Desc, &b.Startpageid)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		fmt.Printf("queryBook() db error (%s)\n", err)
		return nil
	}
	return &b
}

func queryBookName(db *sql.DB, name string) *Book {
	var b Book

	s := "SELECT book_id, name, desc, startpage_id FROM book WHERE name = ?"
	row := db.QueryRow(s, name)
	err := row.Scan(&b.Bookid, &b.Name, &b.Desc, &b.Startpageid)
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

	s := "SELECT page_id, body FROM page WHERE page_id = ? AND book_id = ?"
	row := db.QueryRow(s, pageid, bookid)
	err := row.Scan(&p.Pageid, &p.Body)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		fmt.Printf("queryPage() db error (%s)\n", err)
		return nil
	}
	return &p
}

func createBook(db *sql.DB, b *Book, intro string) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}

	s := "INSERT INTO page (book_id, body) VALUES (?, ?)"
	result, err := txexec(tx, s, 0, intro)
	if handleTxErr(tx, err) {
		return 0, err
	}
	pageid, err := result.LastInsertId()
	if handleTxErr(tx, err) {
		return 0, err
	}

	s = "INSERT INTO book (name, desc, startpage_id) VALUES (?, ?, ?)"
	result, err = txexec(tx, s, b.Name, b.Desc, pageid)
	if handleTxErr(tx, err) {
		return 0, err
	}
	bookid, err := result.LastInsertId()
	if handleTxErr(tx, err) {
		return 0, err
	}

	s = "UPDATE page SET book_id = ? WHERE page_id = ?"
	result, err = txexec(tx, s, bookid, pageid)
	if handleTxErr(tx, err) {
		return 0, err
	}

	err = tx.Commit()
	if handleTxErr(tx, err) {
		return 0, err
	}

	return bookid, nil
}

func createPage(db *sql.DB, bookid int64) (int64, error) {
	s := "INSERT INTO page (book_id, body) VALUES (?, ?)"
	result, err := sqlexec(db, s, bookid, "")
	if err != nil {
		return 0, err
	}
	pageid, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return pageid, nil
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

func printNav(w http.ResponseWriter, r *http.Request, db *sql.DB, login *User, b *Book, pageid int64) {
	if login == nil {
		login = getLoginUser(r, db)
	}
	if b == nil {
		var bookName string
		bookName, pageid = parseBookPageUrl(r.URL.Path)
		if bookName != "" {
			b = queryBookName(db, bookName)
		}
	}

	P := makeFprintf(w)
	P("<header class=\"p-2 bg-gray-800 text-gray-200\">\n")
	P("<nav class=\"flex flex-row justify-between\">\n")

	// Menu section (left part)
	P("<div>\n")
	P("<h1 class=\"inline mr-1\"><a href=\"/\">Game Books</a></h1>\n")
	P("<ul class=\"list-none inline\">\n")
	if b != nil {
		P("  <li class=\"inline mr-2\">\n")
		prevpageids := r.FormValue("prevpageids")
		P("<a class=\"inline italic text-xs link-3 no-underline self-center\" href=\"/bookmarks?bookid=%d&prevpageids=%s&frompageid=%d\">bookmarks</a>\n", b.Bookid, prevpageids, pageid)
		P("  </li>\n")
	}
	P("</ul>\n")
	P("</div>\n")

	// User section (right part)
	P("<div>\n")
	P("<ul class=\"list-none inline text-xs\">\n")
	if login.Userid != -1 {
	}
	if login.Userid == -1 {
		P("<li class=\"inline\"><a href=\"/login\">login</a></li>\n")
	} else if login.Userid == ADMIN_ID {
		P("<li class=\"inline mr-1\"><a href=\"/adminsetup/\">%s</a></li>\n", login.Username)
		P("<li class=\"inline\"><a href=\"/logout\">logout</a></li>\n")
	} else {
		P("<li class=\"inline mr-1\"><a href=\"/usersetup/\">%s</a></li>\n", login.Username)
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
		printNav(w, r, db, login, nil, 0)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <h1 class=\"fg-1 mb-4\">Login</h1>")
		P("      <form class=\"mb-8\" action=\"/login/?from=%s\" method=\"post\">\n", qfrom)
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
		P("          <button class=\"block btn-1 fg-3 bg-3\" type=\"submit\">login</button>\n")
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
		printNav(w, r, db, login, nil, 0)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <h1 class=\"fg-1 mb-4\">Create Account</h1>")
		P("      <form class=\"\" action=\"/createaccount/?from=%s\" method=\"post\">\n", qfrom)
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}
		P("<div class=\"mb-2\">\n")
		P("  <label class=\"block label-1\" for=\"username\">username</label>\n")
		P("  <input class=\"block input-1 w-full\" id=\"username\" name=\"username\" type=\"text\" size=\"20\" value=\"%s\">\n", f.username)
		P("</div>\n")

		P("<div class=\"mb-2\">\n")
		P("  <label class=\"block label-1\" for=\"email\">email</label>\n")
		P("  <input class=\"block input-1 w-full\" id=\"email\" name=\"email\" type=\"email\" size=\"20\" value=\"%s\">\n", f.email)
		P("</div>\n")

		P("<div class=\"mb-2\">\n")
		P("  <label class=\"block label-1\" for=\"password\">password</label>\n")
		P("  <input class=\"block input-1 w-full\" id=\"password\" name=\"password\" type=\"password\" size=\"20\" value=\"%s\">\n", f.password)
		P("</div>\n")

		P("<div class=\"mb-4\">\n")
		P("  <label class=\"block label-1\" for=\"password2\">re-enter password</label>\n")
		P("  <input class=\"block input-1 w-full\" id=\"password2\" name=\"password2\" type=\"password\" size=\"20\" value=\"%s\">\n", f.password2)
		P("</div>\n")

		P("<div class=\"\">\n")
		P("  <button class=\"block btn-1 fg-3 bg-3\">create account</button>\n")
		P("</div>\n")
		P("</form>\n")

		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")
		printFoot(w)
	}
}

func parseBookPageUrl(surl string) (string, int64) {
	var bookName string
	var pageid int64

	sre := `^/(.+?)(?:/(\d*?))?/?$`
	re := regexp.MustCompile(sre)
	matches := re.FindStringSubmatch(surl)
	if matches == nil {
		return bookName, pageid
	}
	bookName = matches[1]
	if len(matches) > 2 && matches[2] != "" {
		pageid = idtoi(matches[2])
	}

	return underscoreToSpace(bookName), pageid
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

		bookName, pageid := parseBookPageUrl(r.URL.Path)
		if bookName == "" {
			printBooksMenu(w, r, db, login)
			return
		}

		b := queryBookName(db, bookName)
		if b == nil {
			http.Error(w, fmt.Sprintf("'%s' not found.", bookName), 404)
			return
		}

		printPage(w, r, db, login, b, pageid)
	}
}

func printBooksMenu(w http.ResponseWriter, r *http.Request, db *sql.DB, login *User) {
	w.Header().Set("Content-Type", "text/html")
	printHead(w, nil, nil)
	printNav(w, r, db, login, nil, 0)

	P := makeFprintf(w)
	P("<section class=\"container main-container\">\n")
	P("  <section class=\"flex flex-row justify-center\">\n")
	P("    <section class=\"widget-1 widget-h flex flex-col py-4 px-8\">\n")
	P("      <article class=\"w-page flex-grow mb-4\">\n")
	P("        <h1 class=\"fg-1 mb-4\">Select Book:</h1>\n")

	s := "SELECT book_id, name, desc FROM book ORDER BY book_id"
	rows, err := db.Query(s)
	if handleDbErr(w, err, "indexhandler") {
		return
	}
	var b Book
	for rows.Next() {
		rows.Scan(&b.Bookid, &b.Name, &b.Desc)
		P("<div class=\"ml-2 mb-4\">\n")
		P("  <div class=\"flex flex-row justify-between\">\n")
		P("    <a class=\"block link-1 no-underline text-base\" href=\"%s\">%s</a>\n", pageUrl(b.Name, 0, ""), b.Name)
		if login.Userid == ADMIN_ID {
			P("    <a class=\"block link-3 text-xs self-center\" href=\"/editbook?bookid=%d\">Edit</a>\n", b.Bookid)
		}
		P("  </div>\n")
		if b.Desc != "" {
			P("  <div class=\"text-xs fg-1\">\n")
			P("%s\n", parseMarkdown(b.Desc))
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

func printPage(w http.ResponseWriter, r *http.Request, db *sql.DB, login *User, b *Book, pageid int64) {
	if pageid == 0 {
		pageid = b.Startpageid
	}

	prevpageids := r.FormValue("prevpageids")

	w.Header().Set("Content-Type", "text/html")
	printHead(w, nil, nil)
	printNav(w, r, db, login, b, pageid)

	P := makeFprintf(w)
	P("<section class=\"container main-container\">\n")
	P("  <section class=\"flex flex-row justify-center\">\n")
	P("    <section class=\"widget-1 widget-h flex flex-col py-4 px-8\">\n")
	P("      <div class=\"flex flex-row justify-between border-b border-gray-500 pb-1 mb-4\">\n")
	P("        <p>\n")
	P("          <span class=\"fg-1 font-bold mr-2\">%s</span>\n", b.Name)
	P("        </p>\n")
	if login.Userid != -1 {
		P("<a class=\"inline italic text-xs link-3 no-underline self-center\" href=\"/createbookmark?bookid=%d&pageid=%d&prevpageids=%s\">%d</a>\n", b.Bookid, pageid, prevpageids, pageid)
	} else {
		P("<span class=\"fg-2 text-xs self-center\">%d</span>\n", pageid)
	}
	P("      </div>\n")

	P("      <article class=\"page w-page flex-grow mb-4\">\n")
	p := queryPage(db, pageid, b.Bookid)
	if p == nil {
		P("<p class=\"fg-2\">Page doesn't exist yet.</p>\n")
	} else {
		var ids string
		if prevpageids != "" {
			ids = fmt.Sprintf("%s,%d", prevpageids, pageid)
		} else {
			ids = fmt.Sprintf("%d", pageid)
		}
		p.Body = convertSrcLinksToMarkdown(p.Body, b.Name, ids)
		if p.Body != "" {
			P("%s\n", parseMarkdown(p.Body))
		} else {
			P("<p class=\"fg-2\">(Empty page)</p>\n")
		}
	}
	P("      </article>\n")

	// Show 'Back' link to previous page.
	// Get last pageid in the list. Ex. ?prevpageids=1,2,3  means prevpageid=3
	var backpageid int64
	var backprevpageids string
	ss := strings.Split(prevpageids, ",")
	if len(ss) > 0 {
		backpageid = idtoi(ss[len(ss)-1])
		backprevpageids = strings.Join(ss[:len(ss)-1], ",")
	}

	P("<div class=\"flex flex-row justify-between pb-1\">\n")
	if backpageid > 0 {
		P("  <a class=\"block italic text-xs link-3 no-underline\" href=\"%s\">&lt;&lt; Back</a>\n", pageUrl(b.Name, backpageid, backprevpageids))
	} else {
		P("  <a class=\"block italic text-xs link-3 no-underline\" href=\"/\">&lt;&lt; Books</a>\n")
	}
	P("  <div></div>\n") // placeholder for right side content
	P("</div>\n")

	if login.Userid == ADMIN_ID {
		P("<div class=\"flex flex-row justify-around bg-3 fg-3 p-1\">\n")
		P("  <ul class=\"list-none text-xs\">\n")
		if p == nil {
			P("    <li class=\"inline\"><a class=\"underline mr-2\" href=\"/createpage?bookid=%d&pageid=%d&prevpageids=%s\">Create Page</a></li>\n", b.Bookid, pageid, prevpageids)
		} else {
			P("    <li class=\"inline\"><a class=\"underline mr-2\" href=\"/editpage?bookid=%d&pageid=%d&prevpageids=%s\">Edit</a></li>\n", b.Bookid, pageid, prevpageids)
		}
		P("  </ul>\n")
		P("</div>\n")
	}

	P("    </section>\n")
	P("  </section>\n")
	P("</section>\n")
	printFoot(w)
}

func bookUrl(bookName string) string {
	return fmt.Sprintf("/%s", url.QueryEscape(spaceToUnderscore(bookName)))
}

func pageUrl(bookName string, pageid int64, prevpageids string) string {
	if pageid <= 0 {
		return fmt.Sprintf("/%s/", url.QueryEscape(spaceToUnderscore(bookName)))
	}
	if prevpageids == "" {
		return fmt.Sprintf("/%s/%d", url.QueryEscape(spaceToUnderscore(bookName)), pageid)
	}
	return fmt.Sprintf("/%s/%d?prevpageids=%s", url.QueryEscape(spaceToUnderscore(bookName)), pageid, prevpageids)
}

func convertSrcLinksToMarkdown(body, bookName string, prevpageids string) string {
	sre := `\[\[(.+?)=>(\d+?)\]\]`
	re := regexp.MustCompile(sre)
	body = re.ReplaceAllString(body, spaceToUnderscore(fmt.Sprintf("[$1](/%s/$2?prevpageids=%s)", bookName, prevpageids)))
	return body
}

// Auto-create pages when the target page id is missing.
// Ex.
//   [[Take the left tunnel]]
// becomes:
//   [[Take the left tunnel=>123]]
// where 123 is the newly created page id.
func insertNewPageLinks(db *sql.DB, body string, bookid int64) (string, error) {
	var reterr error

	sre := `\[\[(.+?)\]\]`
	re := regexp.MustCompile(sre)

	// This code is convuluted because of db error checking,
	// maybe there's a simpler way to rewrite it.
	body = re.ReplaceAllStringFunc(body, func(smatch string) string {
		if reterr != nil {
			return smatch
		}
		if strings.Contains(smatch, "=>") {
			return smatch
		}

		matches := re.FindStringSubmatch(smatch)
		newpageid, err := createPage(db, bookid)
		if err != nil {
			reterr = err
			return smatch
		}
		return fmt.Sprintf("[[%s=>%d]]", matches[1], newpageid)
	})

	return body, reterr
}

func parseMarkdown(s string) string {
	return string(blackfriday.Run([]byte(s), blackfriday.WithExtensions(blackfriday.HardLineBreak)))
}

func createpageHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var body string

		login := getLoginUser(r, db)
		bookid := idtoi(r.FormValue("bookid"))
		pageid := idtoi(r.FormValue("pageid"))
		prevpageids := r.FormValue("prevpageids")

		if login.Userid != ADMIN_ID {
			http.Error(w, "admin user required", 401)
			return
		}
		if bookid == -1 {
			http.Error(w, "bookid required", 401)
			return
		}
		if pageid > 0 {
			if queryPage(db, pageid, bookid) != nil {
				http.Error(w, "page already exists", 401)
				return
			}
		}
		b := queryBook(db, bookid)
		if b == nil {
			http.Error(w, fmt.Sprintf("bookid %d not found", bookid), 401)
			return
		}

		var errmsg string
		if r.Method == "POST" {
			body = strings.TrimSpace(r.FormValue("body"))
			for {
				if body == "" {
					errmsg = "Please enter some text."
					break
				}
				body, err = insertNewPageLinks(db, body, bookid)
				if err != nil {
					http.Error(w, "Server error", 500)
					return
				}

				var result sql.Result
				if pageid > 0 {
					s := "INSERT INTO page (page_id, book_id, body) VALUES (?, ?, ?)"
					result, err = sqlexec(db, s, pageid, bookid, body)
				} else {
					s := "INSERT INTO page (book_id, body) VALUES (?, ?)"
					result, err = sqlexec(db, s, bookid, body)
				}
				if err != nil {
					log.Printf("DB error saving page (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				pageid, _ = result.LastInsertId()
				http.Redirect(w, r, pageUrl(b.Name, pageid, prevpageids), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, b, pageid)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <form class=\"w-editpage\" method=\"post\" action=\"/createpage/?bookid=%d&pageid=%d&prevpageids=%s\">\n", bookid, pageid, prevpageids)
		P("      <h1 class=\"fg-1 mb-4\">Create Page</h1>")
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

		P("  <div class=\"mb-4\">\n")
		P("    <label class=\"block label-1\" for=\"body\">text</label>\n")
		P("    <textarea class=\"block input-1 w-full\" id=\"body\" name=\"body\" rows=\"15\">%s</textarea>\n", body)
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
		var err error

		login := getLoginUser(r, db)
		bookid := idtoi(r.FormValue("bookid"))
		pageid := idtoi(r.FormValue("pageid"))
		prevpageids := r.FormValue("prevpageids")

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
			p.Body = strings.TrimSpace(r.FormValue("body"))
			for {
				if p.Body == "" {
					errmsg = "Please enter some text."
					break
				}
				p.Body, err = insertNewPageLinks(db, p.Body, bookid)
				if err != nil {
					http.Error(w, "Server error", 500)
					return
				}

				var err error
				s := "UPDATE page SET body = ? WHERE page_id = ?"
				_, err = sqlexec(db, s, p.Body, p.Pageid)
				if err != nil {
					log.Printf("DB error saving page (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, pageUrl(b.Name, p.Pageid, prevpageids), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, b, pageid)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <form class=\"w-editpage\" method=\"post\" action=\"/editpage/?bookid=%d&pageid=%d&prevpageids=%s\">\n", bookid, pageid, prevpageids)
		P("      <h1 class=\"fg-1 mb-4\">Edit Page</h1>")
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

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

				_, err := createBook(db, &b, "")
				if err != nil {
					log.Printf("Error saving book (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, pageUrl(b.Name, 0, ""), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, nil, 0)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <form class=\"w-editpage mb-4\" method=\"post\" action=\"/createbook/\">\n")
		P("      <h1 class=\"fg-1 mb-4\">Create Book</h1>")
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
		printNav(w, r, db, login, b, 0)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <form class=\"w-editpage mb-4\" method=\"post\" action=\"/editbook/?bookid=%d\">\n", bookid)
		P("      <h1 class=\"fg-1 mb-4\">Edit Book</h1>")
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

func createbookmarkHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var desc string

		login := getLoginUser(r, db)
		if !validateLogin(w, login) {
			return
		}
		bookid := idtoi(r.FormValue("bookid"))
		pageid := idtoi(r.FormValue("pageid"))
		prevpageids := r.FormValue("prevpageids")

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

		var errmsg string
		if r.Method == "POST" {
			desc = strings.TrimSpace(r.FormValue("desc"))
			for {
				if desc == "" {
					errmsg = "Please enter a bookmark description."
					break
				}

				s := "INSERT INTO bookmark (user_id, book_id, page_id, prevpageids, desc) VALUES (?, ?, ?, ?, ?)"
				_, err = sqlexec(db, s, login.Userid, bookid, pageid, prevpageids, desc)
				if err != nil {
					log.Printf("DB error saving bookmark (%s)\n", err)
					errmsg = "A problem occured. Please try again."
					break
				}
				http.Redirect(w, r, pageUrl(b.Name, pageid, prevpageids), http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, b, pageid)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 p-4\">\n")
		P("      <form class=\"w-createbookmark\" method=\"post\" action=\"/createbookmark/?bookid=%d&pageid=%d&prevpageids=%s\">\n", bookid, pageid, prevpageids)
		P("      <h1 class=\"fg-1 mb-4\">Add Bookmark: <span class=\"font-bold\">%s - page %d</span></h1>", b.Name, pageid)
		if errmsg != "" {
			P("<div class=\"mb-2\">\n")
			P("<p class=\"text-red-500\">%s</p>\n", errmsg)
			P("</div>\n")
		}

		P("  <div class=\"mb-4\">\n")
		P("    <label class=\"block label-1\" for=\"desc\">bookmark description</label>\n")
		P("    <textarea class=\"block input-1 w-full\" id=\"desc\" name=\"desc\" rows=\"5\">%s</textarea>\n", desc)
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

func bookmarksHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		prevpageids := r.FormValue("prevpageids")
		frompageid := idtoi(r.FormValue("frompageid"))

		login := getLoginUser(r, db)
		if !validateLogin(w, login) {
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

		w.Header().Set("Content-Type", "text/html")
		printHead(w, nil, nil)
		printNav(w, r, db, login, b, 0)

		P := makeFprintf(w)
		P("<section class=\"container main-container\">\n")
		P("  <section class=\"flex flex-row justify-center\">\n")
		P("    <section class=\"widget-1 widget-h flex flex-col py-4 px-8\">\n")
		P("      <p class=\"fg-1 border-b border-gray-500 pb-1 mb-4\"><span class=\"font-bold\">%s</span> - Bookmarks</p>\n", b.Name)
		P("      <article class=\"w-page flex-grow mb-4\">\n")

		s := "SELECT book_id, page_id, prevpageids, desc FROM bookmark WHERE user_id = ? AND book_id = ? ORDER BY page_id"
		rows, err := db.Query(s, login.Userid, bookid)
		if handleDbErr(w, err, "bookmarkshandler") {
			return
		}
		var bm Bookmark
		for rows.Next() {
			rows.Scan(&bm.Bookid, &bm.Pageid, &bm.Prevpageids, &bm.Desc)
			P("<div class=\"flex flex-row justify-between border-b border-gray-500 pb-1 ml-2 mb-2\">\n")
			P("  <div class=\"text-sm mr-2\">\n")
			P("    <a class=\"block link-1 no-underline\" href=\"%s\">%s</a>\n", pageUrl(b.Name, bm.Pageid, bm.Prevpageids), parseMarkdown(bm.Desc))
			P("  </div>\n")
			P("  <p class=\"flex-shrink-0\">\n")
			P("    <a class=\"inline link-3 no-underline text-xs self-center mr-1\" href=\"/editbookmark?bookid=%d&prevpageids=%s&frompageid=%d\">Edit</a>\n", bookid, prevpageids, frompageid)
			P("    <a class=\"inline link-3 no-underline text-xs self-center\" href=\"/delbookmark?bookid=%d&prevpageids=%s&frompageid=%d\">Remove</a>\n", bookid, prevpageids, frompageid)
			P("  </p>\n")
			P("</div>\n")
		}
		P("      </article>\n")

		P("<div class=\"flex flex-row justify-between pb-1\">\n")
		if frompageid > 0 {
			P("  <a class=\"block italic text-xs link-3 no-underline\" href=\"%s\">&lt;&lt; Back</a>\n", pageUrl(b.Name, frompageid, prevpageids))
		} else {
			P("  <div></div>\n")
		}
		P("  <div></div>\n") // placeholder for right side content
		P("</div>\n")

		P("    </section>\n")
		P("  </section>\n")
		P("</section>\n")

		printFoot(w)
	}
}
