# Decode polygon block extraData

Small script to decode the **extraData** field of the polygon blocks in order to obtain the **Sealer** (ex miner) of the block.

Special thanks to [startgeek](https://github.com/startgeek), he sent me a working base example and I worked on that.

Usage:

- Takes as argument a [json string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify) of the [block](blockExample.json).

```
go run main.go "{ ... }"
```

This will print the sealer.