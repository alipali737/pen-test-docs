```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
[Apache Tomcat](https://tomcat.apache.org/) is a very common java-based web server. It supports a wide range of frameworks such as Spring and tools such as Gradle.

It is less common to see these exposed to the internet but are considered high value targets on internal networks.

Often these sites have weak or default credentials:
- `tomcat:tomcat`
- `admin:admin`
## Discovery
- `Server` HTTP header in responses
- The 404 page can sometimes leak the version
- `/docs` page 

**Default File Structure**
```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```
> `/bin` : stores scripts and binaries to run the server
> `/conf` : stores config
> `/tomcat-users.xml` : stores user creds and roles
> `/lib` : stores JAR files needed
> `/logs` & `/temp` : stores temp log files
> `/webapps` : default webroot of Tomcat and hosts all the apps
> `/work` : acts as a runtime cache

```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class  
```
> `/WEB-INF/web.xml` : stores info about the routes and classes
> `/WEB-INF/classes` : could have sensitive information in the classes
