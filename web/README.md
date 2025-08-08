# Web UI Directory

This directory contains the web user interface components for TypoSentinel Enterprise.

## Structure

```
web/
├── static/         # Static assets (CSS, JS, images)
├── templates/      # HTML templates
├── assets/         # Build artifacts and bundled assets
└── README.md       # This file
```

## Components

### Static Assets (`static/`)
- CSS stylesheets
- JavaScript files
- Images and icons
- Fonts and other static resources

### Templates (`templates/`)
- HTML templates for web pages
- Partial templates and components
- Layout templates

### Assets (`assets/`)
- Compiled/bundled CSS and JS
- Optimized images
- Generated assets from build process

## Web Server Configuration

The web UI is served by the enterprise server:

```go
router.Static("/static", "./web/static")
router.LoadHTMLGlob("./web/templates/*")
```

## Development

When developing the web UI:

1. Place static files in `static/`
2. Create HTML templates in `templates/`
3. Use the build process to generate optimized assets in `assets/`

## Security

- Static files are served with appropriate security headers
- Templates are protected against XSS attacks
- Assets are served with proper caching headers

## Enterprise Features

The web UI provides access to:
- Dashboard and metrics
- Scan results and reports
- Policy management
- User administration
- Integration configuration