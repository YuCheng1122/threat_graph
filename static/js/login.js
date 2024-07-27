async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);

  const response = await fetch('/api/auth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: formData.toString()
  });

  const data = await response.json();

  if (response.ok) {
    alert('Login successful');
    // Handle successful login
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('controls').style.display = 'block';
    document.getElementById('main').style.display = 'block';
    // Store the token in local storage
    localStorage.setItem('token', data.content.access_token);
  } else {
    alert(`Login failed: ${data.message}`);
  }
}

async function fetchData() {
  const token = localStorage.getItem('token');
  const startTime = document.getElementById('start-time').value;
  const endTime = document.getElementById('end-time').value;

  const response = await fetch(`/api/graph_data?start_time=${encodeURIComponent(startTime)}&end_time=${encodeURIComponent(endTime)}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  if (response.ok) {
    const data = await response.json();
    const cleanedData = cleanData(data);
    renderGraph(cleanedData);
  } else {
    alert('Failed to fetch data');
  }
}
