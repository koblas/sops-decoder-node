# SOPS Decoder for JavaScript (Node)

This is a decoder for [SOPS](https://github.com/mozilla/sops) encoded files. This lightweight encoder makes it easy to embed in your AWS Lambda functions or Docker images without having to bring along the whole Go package.

## Installation

    npm install --save sops-decoder

## Quick Start

```
    const sopsDecode = require('sops-decoder');

    try {
      const data = await sopsDecode.decodeFile('secure.json.enc');

      // do something with the data
    } catch (err) {
      // log a great error
    }

```

### API

    interface Tree {
      [key: string]: any;
    }

    //
    // Take the given path and read the file contents and then call decode on the result
    //
    decodeFile(path: string): Promise<Tree>

    //
    // Run the given tree through the SOPS decoder and return a "plaintext" version of the
    //   result
    //
    decode(tree: Tree): Promise<Tree>


### TODO

[ ] PGP Key support
[ ] Unit Testing
[ ] YAML support for decodeFile()
