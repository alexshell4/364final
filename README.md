SI364 Final Winter 2018

Name: Alexander Shell

This application allows users to search articles from sources of their choosing. From there they are be able to save articles to read later to a reading list. Users are able to see all of the different articles searched for as well the sources. Users are also be able to query articles based on different sources. This is a little bit like a social media application for sharing and finding news. It has diverse functionality in that users can access articles from all the top news sources. The application gets headlines from almost all major news sources using the News API and store the returned data to tables in a database. There are a two many-to-many relationships built in with association tables between the users and reading lists, articles and reading lists. There is also a many-to-one relationship in their respective models between articles and their source. There is also a one-to-many relationship between a user and their reading list.

No additional modules need to be installed in order for this application to run.

ALL Routes

http://localhost:5000/ -> base.html

http://localhost:5000/login -> login.html

http://localhost:5000/logout -> base.html

http://localhost:5000/register -> register.html

http://localhost:5000/register -> 'Only authenticated NewSocial users can do this! Register to log in.'

http://localhost:5000/searchterms -> searchterms.html

http://localhost:5000/source_search -> source_search.html

http://localhost:5000/sourcesearchresults -> source_results.html

http://localhost:5000/articles_searched/<search_term> -> searched_articles.html

http://localhost:5000/create_reading_list -> create_reading_list.html

http://localhost:5000/reading_lists -> reading_lists.html

http://localhost:5000/reading_list/<id_num> -> reading_list.html

http://localhost:5000/update/<title> -> update_article.html

http://localhost:5000/delete/<reading_list> -> reading_lists.html




THINGS I COMPLETED (BOLDED)

 **Ensure that your SI364final.py file has all the setup (app.config values, import statements, code to run the app if that file is run, etc) necessary to run the Flask application, and the application runs correctly on http://localhost:5000 (and the other routes you set up). Your main file must be called SI364final.py, but of course you may include other files if you need.**

 **A user should be able to load http://localhost:5000 and see the first page they ought to see on the application.**

 **Include navigation in base.html with links (using a href tags) that lead to every other page in the application that a user should be able to click on. (e.g. in the lecture examples from the Feb 9 lecture, like this )**

 **Ensure that all templates in the application inherit (using template inheritance, with extends) from base.html and include at least one additional block.**

 **Must use user authentication (which should be based on the code you were provided to do this e.g. in HW4).**

 **Must have data associated with a user and at least 2 routes besides logout that can only be seen by logged-in users.**

 **At least 3 model classes besides the User class.**

 **At least one one:many relationship that works properly built between 2 models.**

 **At least one many:many relationship that works properly built between 2 models.**

 **Successfully save data to each table.**

 **Successfully query data from each of your models (so query at least one column, or all data, from every database table you have a model for) and use it to effect in the application (e.g. won't count if you make a query that has no effect on what you see, what is saved, or anything that happens in the app).**

 **At least one query of data using an .all() method and send the results of that query to a template.**

 **At least one query of data using a .filter_by(... and show the results of that query directly (e.g. by sending the results to a template) or indirectly (e.g. using the results of the query to make a request to an API or save other data to a table).**

 **At least one helper function that is not a get_or_create function should be defined and invoked in the application.**

 **At least two get_or_create functions should be defined and invoked in the application (such that information can be saved without being duplicated / encountering errors).**

 **At least one error handler for a 404 error and a corresponding template.**

 **At least one error handler for any other error (pick one -- 500? 403?) and a corresponding template.**

 **Include at least 4 template .html files in addition to the error handling template files.**

 **At least one Jinja template for loop and at least two Jinja template conditionals should occur amongst the templates.**

 **At least one request to a REST API that is based on data submitted in a WTForm OR data accessed in another way online (e.g. scraping with BeautifulSoup that does accord with other involved sites' Terms of Service, etc).**

 **Your application should use data from a REST API or other source such that the application processes the data in some way and saves some information that came from the source to the database (in some way).**

 **At least one WTForm that sends data with a GET request to a new page.**

 **At least one WTForm that sends data with a POST request to the same page. (NOT counting the login or registration forms provided for you in class.)**

 **At least one WTForm that sends data with a POST request to a new page. (NOT counting the login or registration forms provided for you in class.)**

 **At least two custom validators for a field in a WTForm, NOT counting the custom validators included in the log in/auth code.**

 **Include at least one way to update items saved in the database in the application (like in HW5).**

 **Include at least one way to delete items saved in the database in the application (also like in HW5).**

 **Include at least one use of redirect.**

 **Include at least two uses of url_for. (HINT: Likely you'll need to use this several times, really.)**

 **Have at least 5 view functions that are not included with the code we have provided. (But you may have more! Make sure you include ALL view functions in the app in the documentation and navigation as instructed above.)**

Additional Requirements for additional points -- an app with extra functionality!
Note: Maximum possible % is 102%.

 (100 points) Include a use of an AJAX request in your application that accesses and displays useful (for use of your application) data.

 (100 points) Create, run, and commit at least one migration.

 (100 points) Include file upload in your application and save/use the results of the file. (We did not explicitly learn this in class, but there is information available about it both online and in the Grinberg book.)

 **(100 points) Deploy the application to the internet (Heroku) — only counts if it is up when we grade / you can show proof it is up at a URL and tell us what the URL is in the README. (Heroku deployment as we taught you is 100% free so this will not cost anything.)**

 (100 points) Implement user sign-in with OAuth (from any other service), and include that you need a specific-service account in the README, in the same section as the list of modules that must be installed.
