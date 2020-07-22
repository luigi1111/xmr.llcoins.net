
function showKey(idStr) {
  var x = document.getElementById(idStr);
  if (x.type === "password") {
    x.type = "text";
  } else {
    x.type = "password";
  }
} 
