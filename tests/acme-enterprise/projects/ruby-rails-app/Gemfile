source 'https://rubygems.org'
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

ruby '3.2.0'

# Core Rails framework
gem 'rails', '~> 7.0.8'

# Database
gem 'pg', '~> 1.5'
gem 'redis', '~> 5.0'

# Web server
gem 'puma', '~> 6.4'

# Asset pipeline
gem 'sprockets-rails', '>= 3.4.0'
gem 'sassc-rails', '>= 2.1.0'
gem 'image_processing', '~> 1.12'

# JavaScript
gem 'importmap-rails'
gem 'turbo-rails'
gem 'stimulus-rails'
gem 'jbuilder'

# Authentication & Authorization
gem 'devise', '~> 4.9'
gem 'omniauth', '~> 2.1'
gem 'omniauth-google-oauth2', '~> 1.1'
gem 'omniauth-github', '~> 2.0'
gem 'omniauth-rails_csrf_protection', '~> 1.0'
gem 'cancancan', '~> 3.5'
gem 'pundit', '~> 2.3'

# API
gem 'grape', '~> 1.8'
gem 'grape-entity', '~> 0.10'
gem 'grape_on_rails_routes', '~> 0.3'

# Background Jobs
gem 'sidekiq', '~> 7.1'
gem 'sidekiq-web', '~> 0.0.1'
gem 'sidekiq-cron', '~> 1.10'

# Caching
gem 'redis-rails', '~> 5.0'
gem 'dalli', '~> 3.2'

# File uploads
gem 'carrierwave', '~> 3.0'
gem 'mini_magick', '~> 4.12'
gem 'fog-aws', '~> 3.19'

# Search
gem 'elasticsearch-rails', '~> 7.2'
gem 'elasticsearch-model', '~> 7.2'

# Pagination
gem 'kaminari', '~> 1.2'
gem 'pagy', '~> 6.2'

# Forms
gem 'simple_form', '~> 5.2'
gem 'cocoon', '~> 1.2'

# UI/CSS
gem 'bootstrap', '~> 5.3'
gem 'jquery-rails', '~> 4.6'
gem 'font-awesome-rails', '~> 4.7'

# Utilities
gem 'friendly_id', '~> 5.5'
gem 'paranoia', '~> 2.6'
gem 'acts_as_list', '~> 1.1'
gem 'acts_as_tree', '~> 2.9'
gem 'state_machines-activerecord', '~> 0.8'

# Configuration
gem 'figaro', '~> 1.2'
gem 'dotenv-rails', '~> 2.8'

# Monitoring & Logging
gem 'sentry-ruby', '~> 5.12'
gem 'sentry-rails', '~> 5.12'
gem 'lograge', '~> 0.14'
gem 'amazing_print', '~> 1.5'

# Performance
gem 'bullet', '~> 7.1'
gem 'rack-mini-profiler', '~> 3.1'
gem 'memory_profiler', '~> 1.0'

# HTTP clients
gem 'httparty', '~> 0.21'
gem 'faraday', '~> 2.7'
gem 'rest-client', '~> 2.1'

# JSON
gem 'oj', '~> 3.16'
gem 'multi_json', '~> 1.15'

# XML
gem 'nokogiri', '~> 1.15'
gem 'ox', '~> 2.14'

# Date/Time
gem 'chronic', '~> 0.10'
gem 'ice_cube', '~> 0.16'

# Encryption
gem 'bcrypt', '~> 3.1'
gem 'rbnacl', '~> 7.1'

# PDF generation
gem 'prawn', '~> 2.4'
gem 'prawn-table', '~> 0.2'
gem 'wicked_pdf', '~> 2.7'
gem 'wkhtmltopdf-binary', '~> 0.12'

# Excel/CSV
gem 'roo', '~> 2.10'
gem 'axlsx', '~> 3.0'
gem 'csv', '~> 3.2'

# Email
gem 'mail', '~> 2.8'
gem 'premailer-rails', '~> 1.12'

# Internationalization
gem 'rails-i18n', '~> 7.0'
gem 'i18n-tasks', '~> 1.0'

# Serialization
gem 'active_model_serializers', '~> 0.10'
gem 'fast_jsonapi', '~> 1.5'

# Webhooks
gem 'webhook', '~> 1.0'

# Social media
gem 'twitter', '~> 8.0'
gem 'fb_graph2', '~> 0.19'

# Payment processing
gem 'stripe', '~> 9.4'
gem 'paypal-sdk-rest', '~> 1.7'

# AWS SDK
gem 'aws-sdk-s3', '~> 1.136'
gem 'aws-sdk-ses', '~> 1.62'
gem 'aws-sdk-sns', '~> 1.66'

# Google APIs
gem 'google-apis-drive_v3', '~> 0.45'
gem 'google-apis-gmail_v1', '~> 0.37'

# Machine Learning
gem 'ruby-openai', '~> 5.2'
gem 'tensorflow', '~> 0.1'

# Potentially vulnerable/suspicious gems
gem 'rails', '4.2.11.3'  # Very old Rails version with known vulnerabilities
gem 'actionpack', '4.2.11.3'  # Old ActionPack with vulnerabilities
gem 'activerecord', '4.2.11.3'  # Old ActiveRecord
gem 'nokogiri', '1.10.10'  # Older Nokogiri with vulnerabilities
gem 'loofah', '2.2.3'  # Older Loofah with XSS vulnerabilities
gem 'rack', '1.6.13'  # Old Rack version
gem 'sprockets', '3.7.2'  # Older Sprockets with path traversal
gem 'ffi', '1.9.25'  # Older FFI with vulnerabilities
gem 'rubyzip', '1.3.0'  # Older RubyZip with zip slip vulnerability
gem 'yard', '0.9.20'  # Older YARD with path traversal
gem 'json', '1.8.6'  # Very old JSON gem
gem 'rest-client', '1.6.14'  # Old rest-client with SSL verification issues
gem 'excon', '0.71.1'  # Older Excon with vulnerabilities
gem 'image_processing', '1.9.3'  # Older version with command injection
gem 'carrierwave', '1.3.2'  # Older CarrierWave with file upload vulnerabilities
gem 'devise', '4.6.2'  # Older Devise with timing attack vulnerabilities
gem 'omniauth', '1.9.1'  # Older OmniAuth with CSRF vulnerabilities
gem 'grape', '1.2.5'  # Older Grape with vulnerabilities
gem 'sidekiq', '5.2.9'  # Older Sidekiq
gem 'redis', '4.1.4'  # Older Redis gem
gem 'puma', '3.12.6'  # Older Puma with HTTP smuggling vulnerabilities
gem 'websocket-extensions', '0.1.4'  # Vulnerable WebSocket extensions
gem 'kaminari', '1.1.1'  # Older Kaminari with XSS
gem 'simple_form', '4.1.0'  # Older SimpleForm
gem 'bootstrap-sass', '3.4.1'  # Older Bootstrap with XSS
gem 'jquery-rails', '4.3.5'  # Older jQuery Rails
gem 'turbolinks', '5.2.0'  # Older Turbolinks
gem 'coffee-rails', '4.2.2'  # Older CoffeeScript Rails
gem 'sass-rails', '5.0.7'  # Older Sass Rails
gem 'uglifier', '4.1.20'  # Older Uglifier
gem 'mini_magick', '4.9.5'  # Older MiniMagick with command injection
gem 'rmagick', '4.0.0'  # RMagick with potential vulnerabilities
gem 'paperclip', '6.1.0'  # Deprecated Paperclip with vulnerabilities
gem 'acts_as_commentable', '4.0.2'  # Older gem with potential issues
gem 'friendly_id', '5.2.5'  # Older FriendlyId
gem 'paranoia', '2.4.2'  # Older Paranoia
gem 'cancancan', '2.3.0'  # Older CanCanCan
gem 'pundit', '2.0.1'  # Older Pundit
gem 'doorkeeper', '5.0.3'  # Older Doorkeeper OAuth provider
gem 'oauth2', '1.4.4'  # Older OAuth2 gem
gem 'jwt', '2.1.0'  # Older JWT with vulnerabilities
gem 'bcrypt', '3.1.12'  # Older BCrypt
gem 'mail', '2.7.1'  # Older Mail gem
gem 'prawn', '2.2.2'  # Older Prawn
gem 'roo', '2.8.2'  # Older Roo
gem 'chronic', '0.10.2'  # Older Chronic
gem 'httparty', '0.17.3'  # Older HTTParty
gem 'faraday', '0.17.3'  # Older Faraday
gem 'elasticsearch', '6.8.3'  # Older Elasticsearch client
gem 'redis-rails', '5.0.2'  # Older Redis Rails
gem 'dalli', '2.7.10'  # Older Dalli
gem 'fog-aws', '3.5.2'  # Older Fog AWS
gem 'aws-sdk', '2.11.632'  # Very old AWS SDK v2
gem 'stripe', '4.24.0'  # Older Stripe gem
gem 'paypal-sdk-rest', '1.7.3'  # Older PayPal SDK
gem 'twitter', '6.2.0'  # Older Twitter gem
gem 'sentry-raven', '3.1.2'  # Deprecated Sentry Raven
gem 'newrelic_rpm', '6.15.0'  # Older New Relic
gem 'bugsnag', '6.18.0'  # Older Bugsnag
gem 'rollbar', '2.27.1'  # Older Rollbar

# Typosquatting examples
gem 'railss', '~> 7.0'  # Typo: railss instead of rails
gem 'devize', '~> 4.9'  # Typo: devize instead of devise
gem 'nokogri', '~> 1.15'  # Typo: nokogri instead of nokogiri
gem 'sidekiq-crn', '~> 1.10'  # Typo: crn instead of cron
gem 'bootstrp', '~> 5.3'  # Typo: bootstrp instead of bootstrap
gem 'jqeury-rails', '~> 4.6'  # Typo: jqeury instead of jquery
gem 'carrierwaev', '~> 3.0'  # Typo: carrierwaev instead of carrierwave
gem 'kaminarii', '~> 1.2'  # Typo: kaminarii instead of kaminari
gem 'simple-form', '~> 5.2'  # Typo: hyphen instead of underscore
gem 'friendly-id', '~> 5.5'  # Typo: hyphen instead of underscore

# Suspicious/malicious package names
gem 'backdoor-rails', '~> 1.0'  # Obviously malicious
gem 'rails-exploit', '~> 0.1'  # Suspicious name
gem 'admin-bypass', '~> 2.0'  # Suspicious functionality
gem 'sql-injection-helper', '~> 1.5'  # Malicious helper
gem 'xss-generator', '~> 0.9'  # XSS generation tool
gem 'csrf-bypass', '~> 1.2'  # CSRF bypass tool
gem 'session-hijacker', '~> 0.8'  # Session hijacking
gem 'password-stealer', '~> 1.1'  # Password stealing
gem 'data-exfiltrator', '~> 0.7'  # Data exfiltration
gem 'reverse-shell', '~> 2.1'  # Reverse shell
gem 'keylogger-rails', '~> 1.3'  # Keylogger for Rails

# Internal/private gems (dependency confusion targets)
gem 'acme-utils', '~> 1.0'  # Internal utility gem
gem 'acme-auth', '~> 2.1'  # Internal auth gem
gem 'acme-api-client', '~> 1.5'  # Internal API client
gem 'acme-core', '~> 3.0'  # Internal core gem
gem 'acme-models', '~> 1.8'  # Internal models gem
gem 'acme-helpers', '~> 2.3'  # Internal helpers gem
gem 'acme-config', '~> 1.2'  # Internal config gem
gem 'acme-logger', '~> 1.7'  # Internal logger gem
gem 'acme-mailer', '~> 2.0'  # Internal mailer gem
gem 'acme-workers', '~> 1.4'  # Internal workers gem

group :development, :test do
  # Debugging
  gem 'byebug', platforms: [:mri, :mingw, :x64_mingw]
  gem 'pry', '~> 0.14'
  gem 'pry-byebug', '~> 3.10'
  gem 'pry-rails', '~> 0.3'
  
  # Testing
  gem 'rspec-rails', '~> 6.0'
  gem 'factory_bot_rails', '~> 6.2'
  gem 'faker', '~> 3.2'
  gem 'shoulda-matchers', '~> 5.3'
  gem 'database_cleaner-active_record', '~> 2.1'
  gem 'webmock', '~> 3.19'
  gem 'vcr', '~> 6.2'
  gem 'timecop', '~> 0.9'
  
  # Code quality
  gem 'rubocop', '~> 1.56', require: false
  gem 'rubocop-rails', '~> 2.21', require: false
  gem 'rubocop-rspec', '~> 2.24', require: false
  gem 'rubocop-performance', '~> 1.19', require: false
  gem 'brakeman', '~> 6.0', require: false
  gem 'bundler-audit', '~> 0.9', require: false
  
  # Coverage
  gem 'simplecov', '~> 0.22', require: false
  gem 'simplecov-html', '~> 0.12', require: false
  
  # Environment
  gem 'dotenv-rails', '~> 2.8'
end

group :development do
  # Development tools
  gem 'web-console', '>= 4.1.0'
  gem 'listen', '~> 3.8'
  gem 'spring', '~> 4.1'
  gem 'spring-watcher-listen', '~> 2.1'
  
  # Code analysis
  gem 'rails_best_practices', '~> 1.23'
  gem 'reek', '~> 6.1'
  gem 'flog', '~> 4.6'
  gem 'flay', '~> 2.13'
  
  # Documentation
  gem 'yard', '~> 0.9'
  gem 'redcarpet', '~> 3.6'
  
  # Deployment
  gem 'capistrano', '~> 3.17'
  gem 'capistrano-rails', '~> 1.6'
  gem 'capistrano-passenger', '~> 0.2'
  gem 'capistrano-rbenv', '~> 2.2'
  
  # Email preview
  gem 'letter_opener', '~> 1.8'
  gem 'letter_opener_web', '~> 2.0'
end

group :test do
  # Browser testing
  gem 'capybara', '~> 3.39'
  gem 'selenium-webdriver', '~> 4.13'
  gem 'webdrivers', '~> 5.3'
  
  # API testing
  gem 'rack-test', '~> 2.1'
  
  # Performance testing
  gem 'benchmark-ips', '~> 2.12'
  gem 'benchmark-memory', '~> 0.2'
end

group :production do
  # Production optimizations
  gem 'rack-timeout', '~> 0.6'
  gem 'rack-attack', '~> 6.7'
  
  # Monitoring
  gem 'newrelic_rpm', '~> 9.5'
  gem 'scout_apm', '~> 5.3'
end

# Windows specific gems
gem 'tzinfo-data', platforms: [:mingw, :mswin, :x64_mingw, :jruby]

# Bootsnap for faster boot times
gem 'bootsnap', '>= 1.16.0', require: false