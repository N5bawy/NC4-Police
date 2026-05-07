console.log("NC4 SYSTEM INITIALIZED")

const cards = document.querySelectorAll(".card")

cards.forEach(card => {

  card.addEventListener("mouseenter", () => {

    card.style.transform = "translateY(-8px)"

  })

  card.addEventListener("mouseleave", () => {

    card.style.transform = "translateY(0px)"

  })

})

const announcements = document.querySelectorAll(".announcement")

announcements.forEach(item => {

  item.addEventListener("mouseenter", () => {

    item.style.border = "1px solid #3b82f6"

  })

  item.addEventListener("mouseleave", () => {

    item.style.border = "1px solid transparent"

  })

})

console.log("NC4 READY")
