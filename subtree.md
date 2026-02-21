push
```
git subtree push --prefix=tools/AoiAWD aoiawd master
git subtree split --prefix=tools/AoiAWD --rejoin
```

pull
```
git subtree pull --prefix=tools/AoiAWD aoiawd master --squash
```