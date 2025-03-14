let calendar;

document.addEventListener('DOMContentLoaded', async function () {

    const modal = document.getElementById("notificationModal");
    const closeButton = document.querySelector(".close-button");

    closeButton.addEventListener("click", function () {
        modal.style.display = "none";
    });

    function showNotification(message) {
        document.getElementById("notificationMessage").textContent = message;
        modal.style.display = "block";
    }

    let deleteButtons = document.querySelectorAll(".deleteUserButton");
    deleteButtons.forEach(button => {
        button.addEventListener("click", function () {
            let userId = this.getAttribute("data-user-id");
            deleteUser(userId);
        });
    });

    let toggleAddUserFormButton = document.getElementById("toggleAddUserForm");
    if (toggleAddUserFormButton) {
        toggleAddUserFormButton.addEventListener("click", toggleAddUserForm);
    }

    let addUserButton = document.getElementById("addUserButton");
    if (addUserButton) {
        addUserButton.addEventListener("click", addUser);
    }

    // ✅ FullCalendar Initialization
    let calendarEl = document.getElementById('calendar');
    if (calendarEl) {
        console.log("✅ Initializing FullCalendar...");
        calendar = new FullCalendar.Calendar(calendarEl, {
            initialView: 'dayGridMonth',
            selectable: true,
            themeSystem: "bootstrap5",
            headerToolbar: {
                left: 'prev,next today',
                center: 'title',
                right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek'
            },
            dateClick: function (info) {
                showBookingForm(info.dateStr);
            },
            events: function (fetchInfo, successCallback, failureCallback) {
                let selectedDate = fetchInfo.startStr.split('T')[0];
                fetch(`/getAvailableSlots?date=${selectedDate}`)
                    .then(response => response.json())
                    .then(data => {
                        if (!data.availableSlots || data.availableSlots.length === 0) {
                            console.warn("⚠️ No available slots for this date.");
                            successCallback([]);
                            return;
                        }
                        let events = data.availableSlots.map(slot => ({
                            title: "Available",
                            start: `${selectedDate}T${convertTo24Hour(slot)}`,
                            allDay: false
                        }));
                        successCallback(events);
                    })
                    .catch(error => {
                        console.error("❌ Error fetching available slots:", error);
                        failureCallback(error);
                    });
            }
        });
        calendar.render();
    } else {
        console.log("ℹ️ FullCalendar not needed on this page.");
    }

    let confirmButton = document.getElementById("confirmBookingButton");
    if (confirmButton) {
        confirmButton.addEventListener("click", confirmBooking);
    }

    let bookingData = {}; // Declare bookingData, it was not declared in the original code.

    
    // ✅ Hamburger Menu Toggle
    const hamburger = document.querySelector('.hamburger');
    const navUl = document.querySelector('.site-nav ul');
    if (hamburger && navUl) {
        hamburger.addEventListener('click', function () {
            navUl.classList.toggle('show');
        });
    }
});

document.getElementById("phone").addEventListener("input", function () {
    let phone = this.value.trim();
    let regex = /^\d{10}$/; // 10 digits only
    if (!regex.test(phone)) {
        this.classList.add("is-invalid");
    } else {
        this.classList.remove("is-invalid");
    }
});

function isPastTimeSlot(selectedDate, selectedTime) {
    const now = new Date();
    const selectedDateTime = new Date(`${selectedDate}T${convertTo24Hour(selectedTime)}`); //Fixed line

    if (selectedDateTime < now && selectedDateTime.toDateString() === now.toDateString()) {
        return true;
    }
    return false;
}

async function handleFetchError(response) {
    if (!response.ok) {
        try {
            const errorData = await response.json();
            throw new Error(errorData.message || "An unexpected error occurred.");
        } catch (jsonError) {
            // If parsing JSON fails, handle as a generic error
            throw new Error("An unexpected error occurred.");
        }
    }
}

async function showBookingForm(date) {
    //Convert user selected date to UTC.
    let selectedUtcDate = new Date(date).toISOString().split("T")[0];
    //convert current date to UTC.
    let todayUtc = new Date().toISOString().split("T")[0];

    if (selectedUtcDate < todayUtc) {
        showNotification("You cannot book a past date!", "error");
        return;
    }
    document.getElementById("selectedDate").innerText = "Selected Date: " + date;
    document.getElementById("bookingForm").style.display = "block";
    populateTimeSlots(date);
}

function populateTimeSlots(date) {
    let timeSlotDropdown = document.getElementById("timeSlot");
    if (!timeSlotDropdown) {
        console.error("timeSlot dropdown not found");
        return;
    }
    timeSlotDropdown.innerHTML = '<option value="">Select Time</option>';

    fetch(`/getAvailableSlots?date=${date}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.availableSlots && data.availableSlots.length > 0) {
                data.availableSlots.forEach(slot => {
                    const option = document.createElement('option');
                    option.value = slot;
                    option.textContent = slot;
                    timeSlotDropdown.appendChild(option);
                });
            } else {
                const option = document.createElement('option');
                option.value = "";
                option.textContent = "No slots available";
                timeSlotDropdown.appendChild(option);
            }
        })
        .catch(error => {
            console.error('Error fetching available slots:', error);
            showNotification('Error fetching available slots.', 'error');
        });
}

function convertTo24Hour(time) {
    if (!time) {
        console.error("❌ Invalid time input:", time);
        return "00:00:00"; // Default value
    }

    let match = time.match(/(\d+):(\d+) (\w+)/);
    if (!match) {
        console.error("❌ Invalid time format:", time);
        return "00:00:00"; // Return a fallback value
    }

    let hour = parseInt(match[1], 10);
    let minute = match[2];
    let period = match[3];

    if (period === "PM" && hour !== 12) hour += 12;
    if (period === "AM" && hour === 12) hour = 0;

    return `${hour.toString().padStart(2, '0')}:${minute}:00`;
}

async function confirmBooking() {
    try {
        let name = document.getElementById("name").value.trim();
        let email = document.getElementById("email").value.trim();
        let phone = document.getElementById("phone").value.trim();
        let slotTime = document.getElementById("timeSlot").value.trim();
        let selectedDate = document.getElementById("selectedDate").textContent.replace("Selected Date: ", "").trim();

        if (calendar && calendar.refetchEvents) {
            calendar.refetchEvents();
        } else {
            console.error("Calendar is not initialized or refetchEvents is not a function.");
        }

        if (!name || !email || !phone || !slotTime || !selectedDate) {
            alert("All fields are required!");
            return;
        }
        
        if (phone.length !== 10) {
            showNotification("Phone number must be 10 digits.", "error");
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showNotification("Invalid email format.", "error");
            return; 
        }

        if (isPastTimeSlot(selectedDate, slotTime)) {
            showNotification("You cannot book a past time slot for today.", "error");
            return; // Stop the booking process
        }

        name = name.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        email = email.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        phone = phone.replace(/</g, "&lt;").replace(/>/g, "&gt;");

        let bookingData = { name, email, phone, slot_time: slotTime, date: selectedDate };
        console.log("📡 Booking Data:", bookingData);

        let csrfToken = document.querySelector("input[name='csrf_token']").value;
        const response = await fetch("/bookSlot", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
            body: JSON.stringify(bookingData),
        });
        if (!response.ok) {
            try {
                const errorData = await response.json();
                // Check if the errorData has a message field or specific error details
                if (errorData.message) {
                    showNotification(errorData.message, "error");
                } else {
                    // If no message, try to display all error details
                    let errorDetails = "";
                    for (const key in errorData) {
                        if (errorData.hasOwnProperty(key) && Array.isArray(errorData[key])) {
                            errorDetails += `${key}: ${errorData[key].join(", ")}\n`;
                        }
                    }
                    if (errorDetails) {
                        showNotification(errorDetails.trim(), "error");
                    } else {
                        showNotification("Booking failed. Please check the form and try again.", "error");
                    }
                }
            } catch (parseError) {
                // If parsing JSON fails, show a generic error
                showNotification("Booking failed. Please try again.", "error");
            }
            return;
        }

        const data = await response.json();
        showNotification("✅ " + data.message, "success");

        // ✅ Ensure `calendar` is properly initialized before calling `refetchEvents`
        if (typeof calendar !== "undefined" && calendar !== null) {
            console.log("🔄 Refreshing calendar events...");
            calendar.refetchEvents();
        } else {
            console.warn("⚠️ Calendar is not initialized.");
        }
    } catch (error) {
        console.error("❌ Fetch Error:", error);
        showNotification("Network error occurred.", "error");
    }
}

async function addUser() {
    try {
        const newUsername = document.getElementById("newUsername").value.trim();
        const newPassword = document.getElementById("newPassword").value.trim();
        const newUserRole = document.getElementById("newUserRole").value;
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        if (!newUsername || !newPassword) {
            showNotification("Please enter both username and password.", "error");
            return;
        }

        const response = await fetch('/addUser', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
            body: JSON.stringify({ username: newUsername, password: newPassword, role: newUserRole }),
        });
        await handleFetchError(response);

        const data = await response.json();

        if (data.message === "Username already exists") {
            showNotification("Username already exists. Please choose a different username.", "error");
        } else if (data.message === "User added successfully") {
            showNotification("User added successfully", "success");
            location.reload();
        } else {
            showNotification(data.message, "info");
        }
    } catch (error) {
        console.error("Error adding user:", error);
        showNotification(error.message || "An unexpected error occurred.", "error");
    }
}

async function deleteUser(userId) {
    if (!confirm("Are you sure you want to delete this user?")) return;
    try {
        let csrfToken = document.querySelector("input[name='csrf_token']").value;
        const response = await fetch("/deleteUser", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
            body: JSON.stringify({ id: userId }),
        });
        await handleFetchError(response);
        const data = await response.json();
        showNotification("Success: " + data.message, "success");
        if (data.message.includes("successfully")) location.reload();
    } catch (error) {
        console.error("Error deleting user:", error);
        showNotification("Error: " + error.message, "error");
    }
}

function showNotification(message, type = 'info', duration = 3000) {
    const modal = document.getElementById("notificationModal");
    const modalMessage = document.getElementById("notificationMessage");

    modalMessage.textContent = message;
    modal.classList.remove("success", "error", "info");
    modal.classList.add(type);
    modal.style.display = "block";

    setTimeout(() => {
        modal.style.display = "none";
    }, duration);

    modal.onclick = function() {
        modal.style.display = "none";
    };
}
