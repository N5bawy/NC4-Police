console.log("NC4 SYSTEM LOADED")

const cards = document.querySelectorAll(".card")

cards.forEach(card => {

  card.addEventListener("mouseenter", () => {

    card.style.transform = "translateY(-5px)"
    card.style.transition = ".3s"

  })

  card.addEventListener("mouseleave", () => {

    card.style.transform = "translateY(0px)"

  })

})

const announcements = document.querySelectorAll(".announcement")

announcements.forEach(item => {

  item.addEventListener("mouseenter", () => {

    item.style.border = "1px solid #2196f3"

  })

  item.addEventListener("mouseleave", () => {

    item.style.border = "1px solid transparent"

  })

})

console.log("NC4 READY")
