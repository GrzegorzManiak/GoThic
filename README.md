[![Go Report Card](https://goreportcard.com/badge/github.com/grzegorzmaniak/gothic)](https://goreportcard.com/report/github.com/grzegorzmaniak/gothic)


# GoThic - Go Token Handler for Identity and Control

GoThic is a Go library that provides building blocks for secure session management, CSRF protection, and role-based access control (RBAC) for web applications. It is designed as a flexible, low-level toolkit for developers who need fine-grained control over authentication and authorization behavior.

## Who is this for?

- Developers building web services who need a customizable foundation for session handling, CSRF mitigation, and RBAC.
- Teams that want security primitives they can integrate into their own frameworks and architecture instead of a one-size-fits-all solution.

## What you can do with GoThic

- Implement secure session lifecycle management with encrypted cookies and refresh semantics.
- Enforce CSRF protection using the synchronized token (double-submit) pattern.
- Build flexible RBAC systems with permission caching and pluggable enforcers.
- Integrate a structured request lifecycle that handles session validation, CSRF checks, RBAC enforcement, input binding/validation, and response handling.

## Testing & quality

This project aims for at least 80% code coverage across packages. All sub-modules are tested to meet or exceed that target; testing for the core package is in progress. See TESTING.md for the project's testing strategy and guidelines.

## Documentation

- Implementation and design details are available in DOCS.md.
- Quick start and minimal setup instructions can be found in GETTING_STARTED.md.
- Testing documentation is available in TESTING.md.

## Installation

Run `go get` to install the package into your module (see GETTING_STARTED.md for detailed setup instructions).

## License

This project is released under the terms described in the LICENSE file.
