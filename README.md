# SOPS Decoder for JavaScript (Node)

[![NPM Version](http://img.shields.io/npm/v/sops-decoder.svg?style=flat)](https://www.npmjs.org/package/sops-decoder)
[![NPM Downloads](https://img.shields.io/npm/dm/sops-decoder.svg?style=flat)](https://npmcharts.com/compare/sops-decoder?minimal=true)
[![Build Status](https://circleci.com/gh/koblas/sops-decoder-node/tree/master.svg?style=shield)](https://circleci.com/gh/koblas/sops-decoder-node/tree/master)

This is a decoder for [SOPS](https://github.com/mozilla/sops) encoded files. This lightweight encoder makes it easy to embed in your AWS Lambda functions or Docker images without having to bring along the whole Go package.

*Note: The ```deocodeFile()``` method only supports JSON input.*

## Installation

    npm install --save sops-decoder

## Quick Start

```
    const sopsDecode = require('sops-decoder');

    try {
      const data = await sopsDecode.decodeFile('secure.enc.json');

      // do something with the data
      console.log(JSON.stringify(data, undefined, 2));
    } catch (err) {
      // Handle the error (SopsException)
      console.log(err);
    }

```

### API

    interface Tree {
      [key: string]: any;
    }

    //
    // Take the given path as JSON and read the file contents and then call decode on the result
    //
    decodeFile(path: string): Promise<Tree>

    //
    // Run the given tree through the SOPS decoder and return a "plaintext" version of the
    //   result
    //
    decode(tree: Tree): Promise<Tree>


### TODO

- [ ] PGP Key support
- [ ] Unit Testing
